from burp import IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController
from java.lang import Object
from java.util import ArrayList, HashMap
from javax.swing import (
    JPanel, JSplitPane, JScrollPane,
    DefaultListModel, JList, JMenuItem, SwingUtilities, JCheckBox
)
from javax.swing.event import ListSelectionListener
from java.awt import BorderLayout, Dimension, FlowLayout
from java.awt.event import KeyAdapter, KeyEvent
from threading import Thread
import json
import re

class EndpointSelectionListener(Object, ListSelectionListener):
    def __init__(self, parent): self.parent = parent
    def valueChanged(self, ev):
        if ev.getValueIsAdjusting(): return
        self.parent._on_endpoint_selected()

class CaseSelectionListener(Object, ListSelectionListener):
    def __init__(self, parent): self.parent = parent
    def valueChanged(self, ev):
        if ev.getValueIsAdjusting(): return
        self.parent._on_case_selected()

class DeleteKeyListener(KeyAdapter):
    def __init__(self, parent): self.parent = parent
    def keyPressed(self, ev):
        if ev.getKeyCode() == KeyEvent.VK_DELETE:
            label = self.parent.endpoint_list.getSelectedValue()
            idx = self.parent.endpoint_list.getSelectedIndex()
            if label and idx >= 0:
                self.parent.url_map.remove(label)
                self.parent.endpoint_model.remove(idx)
                self.parent.case_model.clear()
                SwingUtilities.invokeLater(self.parent._clear_editors)

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        # maps label to message
        self.url_map = HashMap()
        # count occurrences per base URL
        self.url_count = HashMap()
        self._init_ui()
        callbacks.addSuiteTab(self)
        callbacks.setExtensionName("TypeXplorer")
        callbacks.registerContextMenuFactory(self)
        self.counter= 0

    def createMenuItems(self, invocation):
        menu = ArrayList()
        menu.add(JMenuItem("Send to TypeXplorer",
            actionPerformed=lambda ev: self._send_to_tab(invocation)))
        return menu

    def _send_to_tab(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages: return
        message = messages[0]
        svc = message.getHttpService()
        info = self._helpers.analyzeRequest(svc, message.getRequest())
        base_url = info.getUrl().toString()
        # increment count for this URL
        self.counter += 1
        label = "%d) %s" % (self.counter, base_url)
        self.url_map.put(label, message)
        self.endpoint_model.addElement(label)

    # ITab methods
    def getTabCaption(self): return "TypeXplorer"
    def getUiComponent(self): return self.main_panel

    # IMessageEditorController
    def getHttpService(self): return getattr(self, 'lastService', None)
    def getRequest(self): return getattr(self, 'lastRequest', None)
    def getResponse(self): return getattr(self, 'lastResponse', None)

    def _init_ui(self):
        self.main_panel = JPanel(BorderLayout())
        self.use_root_checkbox = JCheckBox("Use <root> wrapper")
        ctrl = JPanel(FlowLayout(FlowLayout.LEFT)); ctrl.add(self.use_root_checkbox)
        self.main_panel.add(ctrl, BorderLayout.NORTH)

        self.endpoint_model = DefaultListModel()
        self.endpoint_list = JList(self.endpoint_model)
        self.endpoint_list.setSelectionMode(0)
        self.endpoint_list.addKeyListener(DeleteKeyListener(self))
        left = JScrollPane(self.endpoint_list); left.setPreferredSize(Dimension(300,0))

        self.case_model = DefaultListModel()
        self.case_list = JList(self.case_model); self.case_list.setSelectionMode(0)
        right_list = JScrollPane(self.case_list); right_list.setPreferredSize(Dimension(300,0))

        self.requestViewer = self._callbacks.createMessageEditor(self, False)
        self.responseViewer = self._callbacks.createMessageEditor(self, False)
        self.editors_panel = JSplitPane(JSplitPane.VERTICAL_SPLIT,
            self.requestViewer.getComponent(), self.responseViewer.getComponent())
        self.editors_panel.setResizeWeight(0.5)

        split_lists = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, right_list)
        split_lists.setResizeWeight(0.3)
        split_main = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, split_lists, self.editors_panel)
        split_main.setResizeWeight(0.3)
        self.main_panel.add(split_main, BorderLayout.CENTER)
        self.main_panel.setPreferredSize(Dimension(1000,600))

        self.cases = [
            ("1) header: UrlEncode  body: UrlEncode", "application/x-www-form-urlencoded", "urlencode"),
            ("2) header: UrlEncode  body: JSON", "application/x-www-form-urlencoded", "json"),
            ("3) header: UrlEncode  body: XML", "application/x-www-form-urlencoded", "xml"),
            ("4) header: JSON  body: UrlEncode", "application/json", "urlencode"),
            ("5) header: JSON  body: JSON", "application/json", "json"),
            ("6) header: JSON  body: XML", "application/json", "xml"),
            ("7) header: XML  body: UrlEncode", "application/xml", "urlencode"),
            ("8) header: XML  body: JSON", "application/xml", "json"),
            ("9) header: XML  body: XML", "application/xml", "xml"),
        ]
        self.endpoint_list.getSelectionModel().addListSelectionListener(EndpointSelectionListener(self))
        self.case_list.getSelectionModel().addListSelectionListener(CaseSelectionListener(self))

    def _on_endpoint_selected(self):
        self.case_model.clear()
        for desc, _, _ in self.cases: self.case_model.addElement(desc)
        SwingUtilities.invokeLater(self._clear_editors)

    def _on_case_selected(self):
        idx = self.case_list.getSelectedIndex()
        if idx < 0: return
        label = self.endpoint_list.getSelectedValue()
        message = self.url_map.get(label)
        desc, content_type, body_fmt = self.cases[idx]
        Thread(target=lambda: self._run_case(message, content_type, body_fmt)).start()

    def _clear_editors(self):
        self.requestViewer.setMessage(None, True)
        self.responseViewer.setMessage(None, False)

    def _update_editors(self, req, resp):
        self.requestViewer.setMessage(req, True)
        self.responseViewer.setMessage(resp, False)

    def _run_case(self, message, content_type, body_fmt):
        svc, request = message.getHttpService(), message.getRequest()
        req_str = self._helpers.bytesToString(request)
        analyzed = self._helpers.analyzeRequest(request)
        offset = analyzed.getBodyOffset()
        hdr = req_str[:offset].rstrip('\r\n')
        body = req_str[offset:]
        lines = hdr.split('\r\n')
        req_line = lines[0]
        others = [h for h in lines[1:] if not h.lower().startswith("content-type:")]

        ct_header = next((h for h in lines if h.lower().startswith("content-type:")), None)
        reported_ct = ct_header.split(":",1)[1].strip().lower() if ct_header else ""

        def parse_json(b): return {str(k):str(v) for k,v in json.loads(b).items()}
        def parse_xml(b):
            p = re.compile(r'<(?P<key>[^>\s/]+)>(?P<value>[^<]*)</(?P=key)>')
            return {m.group('key'): m.group('value').strip() for m in p.finditer(b)}
        def parse_form(b):
            d = {}
            for part in b.split('&'):
                if '=' in part:
                    k,v = part.split('=',1)
                    d[k]=v
            return d
        #parse main request body 
        parsers = [parse_form,parse_json, parse_xml]
        for parser in parsers:
            params = {}
            try:
                params = parser(body)
                if len(params) >=1:
                    break
                else:
                    continue   
            except:
                continue

        # rebuild body
        if body_fmt == 'urlencode':
            parts = ['%s=%s' % (k,v) for k,v in params.items()]
            new_body = '&'.join(parts)
        elif body_fmt == 'json':
            new_body = json.dumps(params)
        else:
            parts = ['<%s>%s</%s>' % (k,v,k) for k,v in params.items()]
            if self.use_root_checkbox.isSelected():
                new_body = '<root>' + ''.join(parts) + '</root>'
            else:
                new_body = ''.join(parts)

        # rebuild & send
        content_length = len(new_body.encode('utf-8'))
        new_hdrs = [req_line] + [h for h in others if not h.lower().startswith("content-length:")]
        new_hdrs.append('Content-Type: %s' % content_type)
        new_hdrs.append('Content-Length: %d' % content_length)

        new_req_str = '\r\n'.join(new_hdrs) + '\r\n\r\n' + new_body
        new_req = self._helpers.stringToBytes(new_req_str)
        resp = self._callbacks.makeHttpRequest(svc, new_req)
        self.lastService, self.lastRequest, self.lastResponse = svc, new_req, resp.getResponse()
        SwingUtilities.invokeLater(lambda: self._update_editors(new_req, self.lastResponse))
    def _clear_editors(self):
        # Clear editors by setting empty content (Burp disallows null)
        empty = self._helpers.stringToBytes("")
        self.requestViewer.setMessage(empty, True)
        self.responseViewer.setMessage(empty, False)

    def _update_editors(self, req_bytes, resp_bytes):
        self.requestViewer.setMessage(req_bytes, True)
        self.responseViewer.setMessage(resp_bytes, False)        
