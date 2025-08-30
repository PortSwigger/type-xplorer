from burp import IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController
from java.lang import Object
from java.util import ArrayList, HashMap
from javax.swing import (
    JPanel, JSplitPane, JScrollPane,
    DefaultListModel, JList, JMenuItem, SwingUtilities, JCheckBox, JButton, JLabel, BoxLayout, Box
)
from javax.swing.event import ListSelectionListener
from java.awt import BorderLayout, Dimension, GridLayout, FlowLayout, Insets,GridBagLayout, GridBagConstraints
from java.awt.event import KeyAdapter, KeyEvent
from threading import Thread
import json
import re
import uuid

class EndpointSelectionListener(Object, ListSelectionListener):
    def __init__(self, parent):
        self.parent = parent
    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return
        self.parent._on_endpoint_selected()

class CaseSelectionListener(Object, ListSelectionListener):
    def __init__(self, parent):
        self.parent = parent
    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return
        self.parent._on_case_selected()

class DeleteKeyListener(KeyAdapter):
    def __init__(self, parent):
        self.parent = parent
    def keyPressed(self, event):
        if event.getKeyCode() == KeyEvent.VK_DELETE:
            label = self.parent.endpoint_list_view.getSelectedValue()
            idx = self.parent.endpoint_list_view.getSelectedIndex()
            if label and idx >= 0:
                self.parent.endpoint_message_map.remove(label)
                # Clear cached results for this endpoint
                if label in self.parent.test_results_cache:
                    del self.parent.test_results_cache[label]
                self.parent.endpoint_list_model.remove(idx)
                self.parent.test_case_list_model.clear()
                SwingUtilities.invokeLater(self.parent._clear_editors)

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.endpoint_message_map = HashMap()
        self.selected_test_cases = set()
        # Cache to store test results: {endpoint_label: {(content_type, body_format): (request_bytes, response_bytes)}}
        self.test_results_cache = {}
        self._init_ui()
        callbacks.addSuiteTab(self)
        callbacks.setExtensionName("TypeXplorer")
        callbacks.registerContextMenuFactory(self)
        self.endpoint_counter = 0

    def createMenuItems(self, invocation):
        # Only show the context menu item if exactly one message is selected
        selected_messages = invocation.getSelectedMessages()
        if len(selected_messages) != 1:
            return []  # Return empty list to hide menu items
        
        # Check if request has Content-Length header
        message = selected_messages[0]
        if not self._has_content_length_header(message):
            return []  # Don't show menu if Content-Length is missing
        
        menu = ArrayList()
        menu.add(JMenuItem("Send to TypeXplorer",
            actionPerformed=lambda event: self._send_to_tab(invocation)))
        return menu

    def _has_content_length_header(self, message):
        """
        Check if the request has Content-Length header.
        """
        try:
            request_bytes = message.getRequest()
            if not request_bytes:
                return False
                
            request_string = self._helpers.bytesToString(request_bytes)
            analyzed = self._helpers.analyzeRequest(request_bytes)
            offset = analyzed.getBodyOffset()
            header_lines = request_string[:offset]
            
            # Check if Content-Length header exists
            lines = header_lines.split('\r\n')
            has_content_length = any(h.lower().startswith("content-length:") for h in lines)
            
            return has_content_length
            
        except Exception as e:
            print("TypeXplorer: Error checking Content-Length header - %s" % str(e))
            return False

    def _send_to_tab(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages:
            return
        message = messages[0]
        http_service = message.getHttpService()
        info = self._helpers.analyzeRequest(http_service, message.getRequest())
        base_url = info.getUrl().toString()
        self.endpoint_counter += 1
        label = "%d) %s" % (self.endpoint_counter, base_url)
        self.endpoint_message_map.put(label, message)
        self.endpoint_list_model.addElement(label)
        # Initialize empty cache for this endpoint
        self.test_results_cache[label] = {}
        # Don't automatically run test cases anymore

    def getTabCaption(self):
        return "TypeXplorer"
    def getUiComponent(self):
        return self.typexplorer_panel

    def getHttpService(self):
        return getattr(self, 'last_service', None)
    def getRequest(self):
        return getattr(self, 'last_request', None)
    def getResponse(self):
        return getattr(self, 'last_response', None)

    def _init_ui(self):
        self.typexplorer_panel = JPanel(BorderLayout())

        self.test_case_configs = [
            ("header: UrlEncode  body: UrlEncode", "application/x-www-form-urlencoded", "urlencode"),
            ("header: UrlEncode  body: JSON", "application/x-www-form-urlencoded", "json"),
            ("header: UrlEncode  body: XML", "application/x-www-form-urlencoded", "xml"),
            ("header: UrlEncode  body: form-data", "application/x-www-form-urlencoded", "multipart"),
            ("header: JSON  body: UrlEncode", "application/json", "urlencode"),
            ("header: JSON  body: JSON", "application/json", "json"),
            ("header: JSON  body: XML", "application/json", "xml"),
            ("header: JSON  body: form-data", "application/json", "multipart"),
            ("header: XML  body: UrlEncode", "application/xml", "urlencode"),
            ("header: XML  body: JSON", "application/xml", "json"),
            ("header: XML  body: XML", "application/xml", "xml"),
            ("header: XML  body: form-data", "application/xml", "multipart"),
            ("header: form-data  body: form-data", "multipart/form-data", "multipart"),
            ("header: form-data  body: UrlEncode", "multipart/form-data", "urlencode"),
            ("header: form-data  body: JSON", "multipart/form-data", "json"),
            ("header: form-data  body: XML", "multipart/form-data", "xml"),
            ("header: Text/Plain  body: UrlEncode", "text/plain", "urlencode"),
            ("header: Text/Plain  body: JSON", "text/plain", "json"),
            ("header: Text/Plain  body: XML", "text/plain", "xml"),
            ("header: Text/Plain  body: form-data", "text/plain", "multipart"),
        ]

        self.test_case_to_description = {(h, b): desc for desc, h, b in self.test_case_configs}
        self.description_to_test_case = {desc: (h, b) for desc, h, b in self.test_case_configs}

        content_type_headers = [
            "application/x-www-form-urlencoded",
            "application/json",
            "application/xml",
            "multipart/form-data",
            "text/plain"
        ]
        body_formats = ["urlencode", "json", "xml", "multipart"]
        content_type_labels = ["UrlEncode", "JSON", "XML", "form-data", "Text/Plain"]
        body_format_labels = ["UrlEncode", "JSON", "XML", "form-data"]
        test_case_description_map = {(h, b): desc for desc, h, b in self.test_case_configs}

        table_panel = JPanel(GridBagLayout())
        table_panel.setPreferredSize(Dimension(180, 120))  
        gbc = GridBagConstraints()
        gbc.insets = Insets(1, 5, 1, 5)

        self.test_case_checkboxes = {}

        
        gbc.gridx = 1
        gbc.gridy = 0
        gbc.gridwidth = 4  
        gbc.fill = GridBagConstraints.HORIZONTAL
        body_formats_label = JLabel("Body Formats")
        body_formats_label.setHorizontalAlignment(JLabel.CENTER)
        table_panel.add(body_formats_label, gbc)

        
        gbc.gridwidth = 1
        gbc.fill = GridBagConstraints.NONE

        
        gbc.gridx = 0
        gbc.gridy = 1
        table_panel.add(JPanel(), gbc)

        
        for j, body_label in enumerate(body_format_labels):
            gbc.gridx = j + 1
            table_panel.add(JLabel(body_label), gbc)

        
        for i, header in enumerate(content_type_headers):
            gbc.gridx = 0
            gbc.gridy = i + 2  
            table_panel.add(JLabel(content_type_labels[i]), gbc)
            for j, body in enumerate(body_formats):
                gbc.gridx = j + 1
                if (header, body) in test_case_description_map:
                    checkbox = JCheckBox()
                    checkbox.setToolTipText(test_case_description_map[(header, body)])
                    checkbox.setMargin(Insets(0, 0, 0, 0))
                    checkbox.setPreferredSize(Dimension(20, 20))
                    self.test_case_checkboxes[(header, body)] = checkbox
                    checkbox.addActionListener(lambda event, h=header, b=body: self._on_test_case_changed(h, b))
                    table_panel.add(checkbox, gbc)
                else:
                    table_panel.add(JPanel(), gbc)

        self.endpoint_list_model = DefaultListModel()
        self.endpoint_list_view = JList(self.endpoint_list_model)
        self.endpoint_list_view.setSelectionMode(0)
        self.endpoint_list_view.addKeyListener(DeleteKeyListener(self))
        endpoint_scroll_pane = JScrollPane(self.endpoint_list_view)
        endpoint_scroll_pane.setPreferredSize(Dimension(300, 0))

        self.test_case_list_model = DefaultListModel()
        self.test_case_list_view = JList(self.test_case_list_model)
        test_case_scroll_pane = JScrollPane(self.test_case_list_view)
        test_case_scroll_pane.setPreferredSize(Dimension(350, 300))

        test_case_control_panel = JPanel()
        test_case_control_panel.setLayout(BoxLayout(test_case_control_panel, BoxLayout.Y_AXIS))

        control_button_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        control_button_panel.setLayout(BoxLayout(control_button_panel, BoxLayout.X_AXIS))
        control_button_panel.setPreferredSize(Dimension(350, 50))
        self.xml_root_wrapper_checkbox = JCheckBox("Use <root> wrapper")
        self.xml_root_wrapper_checkbox.setSelected(False)
        select_all_test_cases_button = JButton("Select All")
        select_all_test_cases_button.addActionListener(lambda event: self._select_all_test_cases())
        deselect_all_test_cases_button = JButton("Deselect All")
        deselect_all_test_cases_button.addActionListener(lambda event: self._deselect_all_test_cases())
        
        # Add Test button
        self.test_button = JButton("Test Selected")
        self.test_button.addActionListener(lambda event: self._run_selected_tests())
        self.test_button.setEnabled(False)  # Initially disabled
        
        control_button_panel.add(select_all_test_cases_button)
        control_button_panel.add(Box.createHorizontalStrut(3))
        control_button_panel.add(deselect_all_test_cases_button)
        control_button_panel.add(Box.createHorizontalStrut(3))
        control_button_panel.add(self.test_button)
        control_button_panel.add(Box.createHorizontalStrut(3))
        control_button_panel.add(self.xml_root_wrapper_checkbox)
        
        table_scroll_pane = JScrollPane(table_panel)
        table_scroll_pane.setPreferredSize(Dimension(180, 120))  
        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, control_button_panel, table_scroll_pane)
        split_pane.setResizeWeight(0)
        split_pane.setDividerLocation(400)
        test_case_control_panel.add(split_pane, BorderLayout.CENTER)

        endpoint_and_config_panel = JPanel(BorderLayout())
        split_test_case_endpoint = JSplitPane(JSplitPane.VERTICAL_SPLIT, endpoint_scroll_pane, test_case_scroll_pane)
        split_test_case_endpoint.setResizeWeight(0.5)
        split_test_case_endpoint.setDividerLocation(400)
        endpoint_and_config_panel.add(split_test_case_endpoint, BorderLayout.CENTER)

        self.request_editor = self._callbacks.createMessageEditor(self, True)
        self.response_editor = self._callbacks.createMessageEditor(self, False)
        self.request_response_split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT,
            self.request_editor.getComponent(), self.response_editor.getComponent())
        self.request_response_split_pane.setResizeWeight(0.5)

        endpoint_and_test_case_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
            test_case_control_panel, endpoint_and_config_panel)
        endpoint_and_test_case_split.setResizeWeight(0.5)
        endpoint_and_test_case_split.setDividerLocation(450)

        main_split_pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
            endpoint_and_test_case_split, self.request_response_split_pane)
        main_split_pane.setResizeWeight(0.3)
        self.typexplorer_panel.add(main_split_pane, BorderLayout.CENTER)
        self.typexplorer_panel.setPreferredSize(Dimension(1000, 600))

        self.endpoint_list_view.getSelectionModel().addListSelectionListener(EndpointSelectionListener(self))
        self.test_case_list_view.getSelectionModel().addListSelectionListener(CaseSelectionListener(self))

    def _on_test_case_changed(self, content_type, body_format):
        checkbox = self.test_case_checkboxes.get((content_type, body_format))
        if checkbox.isSelected():
            self.selected_test_cases.add((content_type, body_format))
        else:
            self.selected_test_cases.discard((content_type, body_format))
        
        # Update test button state and test case list
        self._update_test_button_state()
        self._update_test_case_list()

    def _select_all_test_cases(self):
        for (content_type, body_format), checkbox in self.test_case_checkboxes.items():
            checkbox.setSelected(True)
            self.selected_test_cases.add((content_type, body_format))
        self._update_test_button_state()
        self._update_test_case_list()

    def _deselect_all_test_cases(self):
        for checkbox in self.test_case_checkboxes.values():
            checkbox.setSelected(False)
        self.selected_test_cases.clear()
        self._update_test_button_state()
        self._update_test_case_list()
        SwingUtilities.invokeLater(self._clear_editors)

    def _update_test_button_state(self):
        """Enable/disable test button based on selected endpoint and test cases"""
        has_endpoint = self.endpoint_list_view.getSelectedValue() is not None
        has_test_cases = len(self.selected_test_cases) > 0
        self.test_button.setEnabled(has_endpoint and has_test_cases)

    def _update_test_case_list(self):
        """Update the test case list to show selected test cases"""
        label = self.endpoint_list_view.getSelectedValue()
        if label:
            self.test_case_list_model.clear()
            for content_type, body_format in self.selected_test_cases:
                desc = self.test_case_to_description.get((content_type, body_format))
                if desc:
                    # Add visual indicator if test has been run
                    if label in self.test_results_cache and (content_type, body_format) in self.test_results_cache[label]:
                        desc = "[DONE] " + desc
                    self.test_case_list_model.addElement(desc)

    def _run_selected_tests(self):
        """Run all selected test cases for the current endpoint"""
        label = self.endpoint_list_view.getSelectedValue()
        if not label:
            return
            
        message = self.endpoint_message_map.get(label)
        if not message:
            return
        
        # Disable test button during execution
        self.test_button.setEnabled(False)
        self.test_button.setText("Testing...")
        
        def run_tests_thread():
            try:
                for content_type, body_format in self.selected_test_cases:
                    # Only run test if not already cached
                    if label not in self.test_results_cache:
                        self.test_results_cache[label] = {}
                    
                    if (content_type, body_format) not in self.test_results_cache[label]:
                        request_bytes, response_bytes = self._execute_test_case(message, content_type, body_format)
                        self.test_results_cache[label][(content_type, body_format)] = (request_bytes, response_bytes)
                
                # Update UI on completion
                SwingUtilities.invokeLater(lambda: [
                    setattr(self.test_button, 'text', 'Test Selected'),
                    self._update_test_button_state(),
                    self._update_test_case_list()
                ])
                
            except Exception as e:
                print("TypeXplorer: Error running tests - %s" % str(e))
                SwingUtilities.invokeLater(lambda: [
                    setattr(self.test_button, 'text', 'Test Selected'),
                    self._update_test_button_state()
                ])
        
        Thread(target=run_tests_thread).start()

    def _on_endpoint_selected(self):
        self._update_test_case_list()
        # Update checkboxes to reflect current selection
        for (content_type, body_format), checkbox in self.test_case_checkboxes.items():
            checkbox.setSelected((content_type, body_format) in self.selected_test_cases)
        self._update_test_button_state()
        SwingUtilities.invokeLater(self._clear_editors)

    def _on_case_selected(self):
        selected_desc = self.test_case_list_view.getSelectedValue()
        if selected_desc:
            # Remove the [DONE] prefix if present
            desc_clean = selected_desc.replace("[DONE] ", "")
            content_type, body_format = self.description_to_test_case.get(desc_clean)
            if content_type and body_format:
                label = self.endpoint_list_view.getSelectedValue()
                if label and label in self.test_results_cache:
                    # Load from cache if available
                    cached_result = self.test_results_cache[label].get((content_type, body_format))
                    if cached_result:
                        request_bytes, response_bytes = cached_result
                        self.last_service = self.endpoint_message_map.get(label).getHttpService()
                        self.last_request = request_bytes
                        self.last_response = response_bytes
                        SwingUtilities.invokeLater(lambda: self._update_editors(request_bytes, response_bytes))

    def _clear_editors(self):
        empty = self._helpers.stringToBytes("")
        self.request_editor.setMessage(empty, True)
        self.response_editor.setMessage(empty, False)

    def _update_editors(self, request_bytes, response_bytes):
        self.request_editor.setMessage(request_bytes, True)
        self.response_editor.setMessage(response_bytes, False)

    def _execute_test_case(self, message, content_type, body_format):
        """Execute a single test case and return request/response bytes"""
        http_service, request_bytes = message.getHttpService(), message.getRequest()
        request_string = self._helpers.bytesToString(request_bytes)
        analyzed = self._helpers.analyzeRequest(request_bytes)
        offset = analyzed.getBodyOffset()
        header_lines = request_string[:offset].rstrip('\r\n')
        body = request_string[offset:]
        lines = header_lines.split('\r\n')
        req_line = lines[0]
        others = [h for h in lines[1:] if not h.lower().startswith("content-type:")]

        content_type_header = next((h for h in lines if h.lower().startswith("content-type:")), None)
        original_content_type = content_type_header.split(":", 1)[1].strip().lower() if content_type_header else ""

        def parse_json(b):
            try:
                return {str(k): str(v) for k, v in json.loads(b).items()}
            except:
                return {}

        def parse_xml(b):
            try:
                b = re.sub(r'<\?xml[^>]*\?>', '', b).strip()
                p = re.compile(r'<(?P<key>[^>\s/]+)>(?P<value>[^<]*)</(?P=key)>\s*(?=(?:<[^/]|$))', re.DOTALL)
                return {m.group('key'): m.group('value').strip() for m in p.finditer(b)}
            except:
                return {}

        def parse_form(b):
            try:
                d = {}
                for part in b.split('&'):
                    if '=' in part:
                        k, v = part.split('=', 1)
                        d[k] = v
                return d
            except:
                return {}

        def parse_multipart(b, content_type):
            try:
                if not content_type.startswith("multipart/form-data"):
                    return {}
                boundary = "--" + content_type.split("boundary=")[1].strip()
                parts = b.split(boundary)
                d = {}
                for part in parts:
                    if "Content-Disposition" in part:
                        name_match = re.search(r'name="([^"]+)"', part)
                        if name_match:
                            name = name_match.group(1)
                            value_match = re.search(r'\r\n\r\n(.+?)\r\n', part, re.DOTALL)
                            if value_match:
                                d[name] = value_match.group(1).strip()
                return d
            except:
                return {}

        parsers = [
            (parse_form, "application/x-www-form-urlencoded"),
            (parse_json, "application/json"),
            (parse_xml, "application/xml"),
            (parse_multipart, "multipart/form-data")
        ]
        params = {}
        for parser, expected_ct in parsers:
            if original_content_type.startswith(expected_ct) or not params:
                params = parser(body)
                if len(params) >= 1:
                    break

        if body_format == 'urlencode':
            parts = ['%s=%s' % (k, v) for k, v in params.items()]
            new_body = '&'.join(parts)
        elif body_format == 'json':
            new_body = json.dumps(params)
        elif body_format == 'xml':
            parts = ['<%s>%s</%s>' % (k, v, k) for k, v in params.items()]
            xml_body = ''.join(parts)
            if self.xml_root_wrapper_checkbox.isSelected():
                new_body = '<root>' + xml_body + '</root>'
            else:
                new_body = xml_body
        elif body_format == 'multipart':
            boundary = "----WebKitFormBoundary" + str(uuid.uuid4()).replace("-", "")
            parts = []
            for k, v in params.items():
                part = "--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n" % (boundary, k, v)
                parts.append(part)
            parts.append("--%s--\r\n" % boundary)
            new_body = ''.join(parts)
            if content_type == 'multipart/form-data':
                content_type = 'multipart/form-data; boundary=%s' % boundary

        content_length = len(new_body.encode('utf-8'))
        new_headers = [req_line] + [h for h in others if not h.lower().startswith("content-length:")]
        new_headers.append('Content-Type: %s' % content_type)
        new_headers.append('Content-Length: %d' % content_length)

        new_request_string = '\r\n'.join(new_headers) + '\r\n\r\n' + new_body
        new_request_bytes = self._helpers.stringToBytes(new_request_string)
        response_bytes = self._callbacks.makeHttpRequest(http_service, new_request_bytes)
        
        return new_request_bytes, response_bytes.getResponse()