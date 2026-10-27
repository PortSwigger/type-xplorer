# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController, IExtensionStateListener
from java.io import ByteArrayInputStream, ByteArrayOutputStream
from java.lang import InterruptedException, Object, String, Thread, Throwable
from java.util import ArrayList
from java.util.concurrent import Callable, ExecutionException, FutureTask
from java.util.concurrent.atomic import AtomicBoolean
from java.util.zip import GZIPInputStream, Inflater, InflaterInputStream
from javax.swing import (
    JPanel, JSplitPane, JScrollPane,
    DefaultListModel, DefaultListCellRenderer, JList, JMenuItem, SwingUtilities, JCheckBox, JButton, JLabel, BoxLayout, Box
)
from javax.swing.event import ListSelectionListener
from java.awt import BorderLayout, Color, Font, Dimension, FlowLayout, Insets, GridBagLayout, GridBagConstraints
from java.awt.event import KeyAdapter, KeyEvent
from collections import OrderedDict
from threading import Lock
from xml.sax.saxutils import escape as xml_escape
import xml.etree.ElementTree as ET
import jarray
import json
import re
import traceback
import urllib
import uuid


# ---------------------------------------------------------------------------
# Byte / text helpers
#
# Requests are handled as Python 2 "byte strings" (every char is 0-255) so the
# bytes we measure for Content-Length are exactly the bytes we send.
# ---------------------------------------------------------------------------

def _to_str(java_bytes):
    # Constructing a Java String keeps it a java.lang.String; toString() coerces it to a Python unicode
    return String(java_bytes, "ISO-8859-1").toString().encode('latin-1')


def _to_bytes(byte_str):
    return String(byte_str.decode('latin-1')).getBytes("ISO-8859-1")


def _utf8(value):
    if isinstance(value, unicode):
        return value.encode('utf-8')
    if isinstance(value, str):
        return value
    return str(value)


def _to_text(value):
    """Scalar/nested value -> utf-8 byte string for the text based formats."""
    if value is None:
        return ''
    if isinstance(value, basestring):
        return _utf8(value)
    return _dumps(value)


def _to_unicode(value):
    """Recursively decode byte strings (utf-8, else latin-1) so json can always serialize them."""
    if isinstance(value, str):
        try:
            return value.decode('utf-8')
        except UnicodeDecodeError:
            return value.decode('latin-1')
    if isinstance(value, dict):
        return OrderedDict((_to_unicode(k), _to_unicode(v)) for k, v in value.items())
    if isinstance(value, list):
        return [_to_unicode(v) for v in value]
    return value


def _dumps(value):
    return json.dumps(_to_unicode(value))


def _is_scalar(value):
    return not isinstance(value, (dict, list))


def _add(params, key, value):
    """Insert a value, turning repeated keys into lists instead of dropping them."""
    if key in params:
        if isinstance(params[key], list):
            params[key].append(value)
        else:
            params[key] = [params[key], value]
    else:
        params[key] = value


def _pairs(params):
    """Flatten params into (key, text) pairs; lists of scalars repeat the key."""
    for key, value in params.items():
        key = _utf8(key)
        if isinstance(value, list) and all(_is_scalar(v) for v in value):
            for item in value:
                yield key, _to_text(item)
        else:
            yield key, _to_text(value)


class ParseError(Exception):
    pass


# ---------------------------------------------------------------------------
# Transfer / content encodings: undo them so the parsers see the real body
# ---------------------------------------------------------------------------

MAX_DECODED_BYTES = 16 * 1024 * 1024


def _header_values(header_lines, name):
    prefix = name.lower() + ':'
    return [h.split(':', 1)[1].strip().lower() for h in header_lines if h.lower().startswith(prefix)]


def _dechunk(body):
    out = []
    pos = 0
    while True:
        if pos >= len(body):  # last-chunk marker missing, take what we have
            return ''.join(out)
        eol = body.find('\n', pos)
        if eol < 0:
            raise ParseError("malformed chunked body")
        try:
            size = int(body[pos:eol].split(';', 1)[0].strip(), 16)
        except ValueError:
            raise ParseError("malformed chunked body")
        pos = eol + 1
        if size == 0:
            return ''.join(out)
        if pos + size > len(body):
            raise ParseError("truncated chunked body")
        out.append(body[pos:pos + size])
        pos += size
        if body.startswith('\r\n', pos):
            pos += 2
        elif body.startswith('\n', pos):
            pos += 1


def _read_all(stream):
    out = ByteArrayOutputStream()
    buf = jarray.zeros(8192, 'b')
    while True:
        count = stream.read(buf)
        if count < 0:
            break
        out.write(buf, 0, count)
        if out.size() > MAX_DECODED_BYTES:
            raise ParseError("decoded body is larger than %d bytes" % MAX_DECODED_BYTES)
    return _to_str(out.toByteArray())


def _inflate(body, encoding):
    data = _to_bytes(body)
    try:
        if encoding == 'gzip':
            return _read_all(GZIPInputStream(ByteArrayInputStream(data)))
        try:  # "deflate" is zlib-wrapped by spec, but some servers send a raw stream
            return _read_all(InflaterInputStream(ByteArrayInputStream(data)))
        except Throwable:
            return _read_all(InflaterInputStream(ByteArrayInputStream(data), Inflater(True)))
    except ParseError:
        raise
    except Throwable as e:
        raise ParseError("could not decode %s body: %s" % (encoding, e))


def decode_body(body, header_lines):
    if 'chunked' in ','.join(_header_values(header_lines, 'transfer-encoding')):
        body = _dechunk(body)
    encodings = [e.strip() for e in ','.join(_header_values(header_lines, 'content-encoding')).split(',')]
    for encoding in reversed([e for e in encodings if e and e != 'identity']):  # last applied, first undone
        if encoding in ('gzip', 'x-gzip'):
            body = _inflate(body, 'gzip')
        elif encoding == 'deflate':
            body = _inflate(body, 'deflate')
        else:
            raise ParseError("unsupported Content-Encoding: %s" % encoding)
    return body


# ---------------------------------------------------------------------------
# Parsers: body (byte string) -> OrderedDict, or None when the body does not fit
# ---------------------------------------------------------------------------

def parse_form(body):
    params = OrderedDict()
    for piece in body.strip().split('&'):
        if not piece:
            continue
        # A bare "flag" (no "=") is kept as an empty value instead of being dropped
        key, _, value = piece.partition('=')
        _add(params, urllib.unquote_plus(key), urllib.unquote_plus(value))
    return params


class _Duplicates(list):
    """Values of a JSON key that appears more than once (kept apart from real arrays)."""


def _json_pairs(pairs):
    """object_pairs_hook: keep key order and do not lose repeated keys."""
    obj = OrderedDict()
    for key, value in pairs:
        key = _utf8(key)
        if key not in obj:
            obj[key] = value
        elif isinstance(obj[key], _Duplicates):
            obj[key].append(value)
        else:
            obj[key] = _Duplicates([obj[key], value])
    return obj


def parse_json(body):
    try:
        try:
            text = body.decode('utf-8')
        except UnicodeDecodeError:
            text = body.decode('latin-1')
        data = json.loads(text, object_pairs_hook=_json_pairs)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    return data


# Namespace prefixes ("soap:Body") are unbound once we wrap the body, so the colon is
# swapped for a marker while parsing and turned back into ":" when writing XML.
_NS_MARK = '__ns__'
_TAG_RE = re.compile(r'<[^<>!?][^<>]*>')
_QNAME_RE = re.compile(r'("[^"]*"|\'[^\']*\')|([A-Za-z_][\w.\-]*):([A-Za-z_][\w.\-]*)')


def _hide_prefixes(body):
    def fix_tag(tag):
        return _QNAME_RE.sub(lambda q: q.group(1) or q.group(2) + _NS_MARK + q.group(3), tag.group(0))
    return _TAG_RE.sub(fix_tag, body)


def _xml_value(element):
    """Leaf without attributes -> text; otherwise a dict with "@attr" and "#text" entries."""
    text = _utf8((element.text or '').strip())
    attributes = [('@' + _utf8(k), _utf8(v)) for k, v in element.attrib.items()]
    if len(element) == 0 and not attributes:
        return text
    nested = OrderedDict(attributes)
    for child in element:
        _add(nested, _utf8(child.tag), _xml_value(child))
    if text:
        nested['#text'] = text
    return nested


def parse_xml(body):
    body = re.sub(r'^\s*<\?xml[^>]*\?>', '', body).strip()
    if not body:
        return None
    # Never feed DOCTYPE/entity declarations to the parser inside Burp
    if '<!DOCTYPE' in body.upper() or '<!ENTITY' in body.upper():
        raise ParseError("XML bodies with DOCTYPE/ENTITY declarations are not supported")
    try:
        wrapper = ET.fromstring('<__r>' + _hide_prefixes(body) + '</__r>')
    except Exception:
        return None
    children = list(wrapper)
    # A single element that itself has children is the document's own root
    node = children[0] if len(children) == 1 and len(children[0]) > 0 else wrapper
    params = OrderedDict()
    for child in node:
        _add(params, _utf8(child.tag), _xml_value(child))
    return params


def parse_multipart(body, content_type):
    match = re.search(r'boundary=(?:"([^"]+)"|([^;\s]+))', content_type, re.I)
    if match:
        boundary = match.group(1) or match.group(2)
    else:
        first_line = re.split(r'\r?\n', body.lstrip(), 1)[0]
        if not first_line.startswith('--'):
            return None
        boundary = first_line[2:].strip()
    params = OrderedDict()
    for part in body.split('--' + boundary):
        if part.startswith('--'):  # closing delimiter
            continue
        if part.startswith('\r\n'):
            part = part[2:]
        elif part.startswith('\n'):
            part = part[1:]
        sep = part.find('\r\n\r\n')
        sep_len = 4
        if sep < 0:
            sep = part.find('\n\n')
            sep_len = 2
        if sep < 0:
            continue
        headers, value = part[:sep], part[sep + sep_len:]
        name = re.search(r'(?:^|[;\s])name="([^"]*)"', headers, re.I)
        if not name:
            continue
        if value.endswith('\r\n'):
            value = value[:-2]
        elif value.endswith('\n'):
            value = value[:-1]
        _add(params, name.group(1), value)
    return params


def parse_body(body, content_type):
    """Pick the parser from the original Content-Type, falling back to the others."""
    ct = content_type.lower()
    if body.startswith('\xef\xbb\xbf'):  # UTF-8 BOM
        body = body[3:]
    sniffed = body.lstrip()[:2]
    # A parser is only tried when the body plausibly is that format, otherwise the lenient
    # form parser would turn e.g. an unparsable XML body into garbage key/value pairs
    plausible = {
        'form': sniffed[:1] not in ('{', '[', '<') and not sniffed.startswith('--'),
        'json': sniffed[:1] == '{',
        'xml': sniffed[:1] == '<',
        'multipart': sniffed.startswith('--') or 'boundary=' in ct,
    }
    if 'json' in ct:
        first = 'json'
    elif 'xml' in ct:
        first = 'xml'
    elif 'multipart/form-data' in ct:
        first = 'multipart'
    elif 'x-www-form-urlencoded' in ct:
        first = 'form'
    elif sniffed.startswith('{'):
        first = 'json'
    elif sniffed.startswith('<'):
        first = 'xml'
    elif sniffed.startswith('--'):
        first = 'multipart'
    else:
        first = 'form'

    parsers = {
        'form': parse_form,
        'json': parse_json,
        'xml': parse_xml,
        'multipart': lambda b: parse_multipart(b, content_type),
    }
    order = [first] + [n for n in ('form', 'json', 'xml', 'multipart') if n != first]
    for name in order:
        if not plausible[name]:
            continue
        params = parsers[name](body)
        if params:
            return params
    raise ParseError("could not parse the original body (content-type: %s)" % (content_type or "none"))


# ---------------------------------------------------------------------------
# Serializers: OrderedDict -> body (byte string)
# ---------------------------------------------------------------------------

def to_urlencode(params):
    return '&'.join('%s=%s' % (urllib.quote(k, safe=""), urllib.quote(v, safe="")) for k, v in _pairs(params))


def to_json(params):
    return _dumps(params)


def _xml_name(name):
    parts = []
    for part in _utf8(name).split(_NS_MARK):  # prefix and local name are checked separately
        part = re.sub(r'[^A-Za-z0-9_.\-]', '_', part)
        if not part or not (part[0].isalpha() or part[0] == '_'):
            part = '_' + part
        parts.append(part)
    return ':'.join(parts)


def _xml_element(name, value):
    name = _xml_name(name)
    if isinstance(value, list):
        return ''.join(_xml_element(name, v) for v in value)
    if isinstance(value, dict):
        attributes, text, children = '', '', []
        for k, v in value.items():
            k = _utf8(k)
            if k.startswith('@') and _is_scalar(v):
                attributes += ' %s="%s"' % (_xml_name(k[1:]), xml_escape(_to_text(v), {'"': '&quot;'}))
            elif k == '#text' and _is_scalar(v):
                text = xml_escape(_to_text(v))
            else:
                children.append(_xml_element(k, v))
        return '<%s%s>%s%s</%s>' % (name, attributes, text, ''.join(children), name)
    return '<%s>%s</%s>' % (name, xml_escape(_to_text(value)), name)


def to_xml(params, wrap_root):
    body = ''.join(_xml_element(k, v) for k, v in params.items())
    return '<root>' + body + '</root>' if wrap_root else body


def to_multipart(params, boundary):
    parts = ['--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n'
             % (boundary, k.replace('"', '%22'), v) for k, v in _pairs(params)]
    parts.append('--%s--\r\n' % boundary)
    return ''.join(parts)


# ---------------------------------------------------------------------------
# Swing listeners
# ---------------------------------------------------------------------------

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


class StatusCellRenderer(DefaultListCellRenderer):
    """Colors a case by the status code in its "[200] ..." prefix"""
    COLORS = {
        '2': Color(0, 150, 60),      # success: green
        '3': Color(30, 100, 220),    # redirect: blue
        '4': Color(225, 120, 120),   # client error: soft red
        '5': Color(200, 0, 0),       # server error: strong red
    }
    ERROR_COLOR = Color(180, 100, 0)

    def getListCellRendererComponent(self, jlist, value, index, isSelected, cellHasFocus):
        component = DefaultListCellRenderer.getListCellRendererComponent(
            self, jlist, value, index, isSelected, cellHasFocus)
        text = value or u""
        color = None
        if text.startswith(u"[ERR]"):
            color = self.ERROR_COLOR
        elif len(text) > 1 and text[0] == u"[" and text[1] in self.COLORS:
            color = self.COLORS[text[1]]
        if color is not None:
            if isSelected:
                component.setBackground(color)
                component.setForeground(Color.WHITE)
            else:
                component.setForeground(color)
            component.setFont(component.getFont().deriveFont(Font.BOLD))
        return component


class DeleteKeyListener(KeyAdapter):
    def __init__(self, parent):
        self.parent = parent

    def keyPressed(self, event):
        if event.getKeyCode() == KeyEvent.VK_DELETE:
            self.parent._delete_selected_endpoint()


class _HttpCall(Callable):
    """Wraps makeHttpRequest so it can run on a helper thread behind a FutureTask"""

    def __init__(self, callbacks, http_service, request_bytes):
        self.callbacks = callbacks
        self.http_service = http_service
        self.request_bytes = request_bytes

    def call(self):
        return self.callbacks.makeHttpRequest(self.http_service, self.request_bytes)


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.endpoint_message_map = {}   # label -> saved IHttpRequestResponse
        self.selected_cases = {}         # label -> set((content_type, body_format))
        # {label: {(content_type, body_format, xml_wrapped): (request, response, status, error)}}
        # Shared with the worker thread: only touch it while holding _cache_lock
        self.test_results_cache = {}
        self._cache_lock = Lock()
        self.endpoint_counter = 0
        self._visible_cases = []         # cases shown in the case list, same order as the list model
        self._shown = None               # (label, case, result) currently loaded in the editors
        self._running = AtomicBoolean(False)
        self._unloaded = AtomicBoolean(False)
        self._worker = None              # java.lang.Thread running the tests, kept so unload can interrupt it
        self.last_service = None
        self.last_request = None
        self.last_response = None
        self._init_ui()
        callbacks.setExtensionName("TypeXplorer")
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerExtensionStateListener(self)

    def extensionUnloaded(self):
        self._unloaded.set(True)
        worker = self._worker
        if worker is not None:
            worker.interrupt()  # aborts the wait on an in-flight request, see _make_http_request

    def createMenuItems(self, invocation):
        # Only show the context menu item if exactly one message with a body is selected
        selected_messages = invocation.getSelectedMessages()
        if not selected_messages or len(selected_messages) != 1:
            return []
        if not self._has_body(selected_messages[0]):
            return []

        menu = ArrayList()
        menu.add(JMenuItem("Send to TypeXplorer",
            actionPerformed=lambda event: self._send_to_tab(invocation)))
        return menu

    def _has_body(self, message):
        try:
            request_bytes = message.getRequest()
            if not request_bytes:
                return False
            offset = self._helpers.analyzeRequest(request_bytes).getBodyOffset()
            return len(request_bytes) > offset
        except Exception as e:
            self._callbacks.printError("TypeXplorer: error checking request body - %s" % e)
            return False

    def _send_to_tab(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages:
            return
        original = messages[0]

        def save_thread():
            try:
                # Keep our own copy: the original message object may be changed or released later.
                # This writes the whole message to disk, so it stays off the UI thread.
                message = self._callbacks.saveBuffersToTempFiles(original)
                url = self._helpers.analyzeRequest(message.getHttpService(), message.getRequest()).getUrl().toString()
            except Exception:
                self._callbacks.printError("TypeXplorer: %s" % traceback.format_exc())
                return
            SwingUtilities.invokeLater(lambda: self._add_endpoint(message, url))

        saver = Thread(save_thread, "TypeXplorer-save")
        saver.setDaemon(True)
        saver.start()

    def _add_endpoint(self, message, url):
        if self._unloaded.get():
            return
        self.endpoint_counter += 1
        label = "%d) %s" % (self.endpoint_counter, url)
        self.endpoint_message_map[label] = message
        self.selected_cases[label] = set()
        with self._cache_lock:
            self.test_results_cache[label] = {}
        self.endpoint_list_model.addElement(label)
        self.endpoint_list_view.setSelectedIndex(self.endpoint_list_model.getSize() - 1)

    def getTabCaption(self):
        return "TypeXplorer"

    def getUiComponent(self):
        return self.typexplorer_panel

    def getHttpService(self):
        return self.last_service

    def getRequest(self):
        return self.last_request

    def getResponse(self):
        return self.last_response

    def _init_ui(self):
        self.typexplorer_panel = JPanel(BorderLayout())

        content_type_headers = [
            "application/x-www-form-urlencoded",
            "application/json",
            "application/xml",
            "multipart/form-data",
            "text/plain"
        ]
        body_formats = ["urlencode", "json", "xml", "multipart"]
        content_type_labels = [u"URL-Encoded", u"JSON", u"XML", u"Form-Data", u"Plain Text"]
        body_format_labels = [u"URL-Encoded", u"JSON", u"XML", u"Form-Data"]

        # One test case per header/body pair, e.g. "Header: JSON  ->  Body: XML"
        self.test_case_configs = [
            (u"Header: %s  →  Body: %s" % (content_type_labels[i], body_format_labels[j]), header, body)
            for i, header in enumerate(content_type_headers)
            for j, body in enumerate(body_formats)
        ]

        self.test_case_to_description = {(h, b): desc for desc, h, b in self.test_case_configs}

        table_panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(1, 5, 1, 5)

        self.test_case_checkboxes = {}

        gbc.gridx = 1
        gbc.gridy = 0
        gbc.gridwidth = 4
        gbc.fill = GridBagConstraints.HORIZONTAL
        body_formats_label = JLabel(u"Body Format  ↓")
        body_formats_label.setHorizontalAlignment(JLabel.CENTER)
        table_panel.add(body_formats_label, gbc)

        gbc.gridwidth = 1
        gbc.fill = GridBagConstraints.NONE

        gbc.gridx = 0
        gbc.gridy = 1
        corner_label = JLabel(u"Content-Type  ↓")
        corner_label.setFont(corner_label.getFont().deriveFont(Font.BOLD))
        table_panel.add(corner_label, gbc)

        for j, body_label in enumerate(body_format_labels):
            gbc.gridx = j + 1
            column_label = JLabel(body_label)
            column_label.setFont(column_label.getFont().deriveFont(Font.BOLD))
            table_panel.add(column_label, gbc)

        for i, header in enumerate(content_type_headers):
            gbc.gridx = 0
            gbc.gridy = i + 2
            row_label = JLabel(content_type_labels[i])
            row_label.setFont(row_label.getFont().deriveFont(Font.BOLD))
            table_panel.add(row_label, gbc)
            for j, body in enumerate(body_formats):
                gbc.gridx = j + 1
                if (header, body) in self.test_case_to_description:
                    checkbox = JCheckBox()
                    checkbox.setToolTipText(self.test_case_to_description[(header, body)])
                    checkbox.setMargin(Insets(0, 0, 0, 0))
                    checkbox.setPreferredSize(Dimension(20, 20))
                    checkbox.setEnabled(False)  # needs a selected endpoint
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
        self.test_case_list_view.setSelectionMode(0)
        self.test_case_list_view.setCellRenderer(StatusCellRenderer())
        test_case_scroll_pane = JScrollPane(self.test_case_list_view)
        test_case_scroll_pane.setPreferredSize(Dimension(350, 300))

        test_case_control_panel = JPanel(BorderLayout())

        self.xml_root_wrapper_checkbox = JCheckBox(u"Wrap XML body in <root>")
        self.xml_root_wrapper_checkbox.setSelected(False)
        # Results depend on this option, so show the matching cached status
        self.xml_root_wrapper_checkbox.addActionListener(lambda event: self._update_test_case_list())
        self.select_all_button = JButton("Select All")
        self.select_all_button.addActionListener(lambda event: self._select_all_test_cases())
        self.deselect_all_button = JButton("Deselect All")
        self.deselect_all_button.addActionListener(lambda event: self._deselect_all_test_cases())
        self.select_all_button.setEnabled(False)
        self.deselect_all_button.setEnabled(False)

        self.test_button = JButton("Test Selected")
        self.test_button.addActionListener(lambda event: self._run_selected_tests())
        self.test_button.setEnabled(False)

        # Row 1: actions, row 2: options. Stacked so nothing gets clipped in a narrow pane.
        button_row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        button_row.add(self.select_all_button)
        button_row.add(self.deselect_all_button)
        button_row.add(self.test_button)
        option_row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        option_row.add(self.xml_root_wrapper_checkbox)

        toolbar = JPanel()
        toolbar.setLayout(BoxLayout(toolbar, BoxLayout.Y_AXIS))
        toolbar.add(button_row)
        toolbar.add(option_row)

        # Grid keeps its natural size at the top of the scroll area instead of being stretched
        grid_holder = JPanel(BorderLayout())
        grid_holder.add(table_panel, BorderLayout.NORTH)
        table_scroll_pane = JScrollPane(grid_holder)

        test_case_control_panel.add(toolbar, BorderLayout.NORTH)
        test_case_control_panel.add(table_scroll_pane, BorderLayout.CENTER)

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

    # -- selection state ----------------------------------------------------

    def _current_label(self):
        return self.endpoint_list_view.getSelectedValue()

    def _current_selection(self):
        label = self._current_label()
        if label is None:
            return None
        return self.selected_cases.setdefault(label, set())

    def _sync_checkboxes(self):
        label = self._current_label()
        selection = self.selected_cases.get(label, set()) if label else set()
        for case, checkbox in self.test_case_checkboxes.items():
            checkbox.setSelected(case in selection)
            checkbox.setEnabled(label is not None)
        self.select_all_button.setEnabled(label is not None)
        self.deselect_all_button.setEnabled(label is not None)

    def _on_test_case_changed(self, content_type, body_format):
        selection = self._current_selection()
        if selection is None:
            return
        checkbox = self.test_case_checkboxes.get((content_type, body_format))
        if checkbox.isSelected():
            selection.add((content_type, body_format))
        else:
            selection.discard((content_type, body_format))
        self._update_test_button_state()
        self._update_test_case_list()

    def _select_all_test_cases(self):
        selection = self._current_selection()
        if selection is None:
            return
        selection.update(self.test_case_checkboxes.keys())
        self._sync_checkboxes()
        self._update_test_button_state()
        self._update_test_case_list()

    def _deselect_all_test_cases(self):
        selection = self._current_selection()
        if selection is None:
            return
        selection.clear()
        self._sync_checkboxes()
        self._update_test_button_state()
        self._update_test_case_list()
        self._clear_editors()

    def _update_test_button_state(self):
        """Enable/disable test button based on selected endpoint, test cases and a running job"""
        selection = self._current_selection()
        self.test_button.setEnabled(not self._running.get() and bool(selection))

    def _delete_selected_endpoint(self):
        label = self._current_label()
        idx = self.endpoint_list_view.getSelectedIndex()
        if label is None or idx < 0:
            return
        self.endpoint_message_map.pop(label, None)
        self.selected_cases.pop(label, None)
        with self._cache_lock:
            self.test_results_cache.pop(label, None)
        self.endpoint_list_model.remove(idx)
        self._on_endpoint_selected()

    # -- result list ----------------------------------------------------------

    def _cache_key(self, case):
        # The <root> wrapper only changes XML bodies, so only those depend on it
        wrap = self.xml_root_wrapper_checkbox.isSelected() if case[1] == "xml" else False
        return (case[0], case[1], wrap)

    def _lookup_result(self, label, case):
        key = self._cache_key(case)
        with self._cache_lock:
            return self.test_results_cache.get(label, {}).get(key)

    def _update_test_case_list(self):
        """Show the endpoint's selected test cases, prefixed with the response status code"""
        label = self._current_label()
        cases, entries = [], []
        if label is not None:
            selection = self.selected_cases.get(label, set())
            for desc, header, body in self.test_case_configs:
                case = (header, body)
                if case not in selection:
                    continue
                result = self._lookup_result(label, case)
                prefix = "[%s] " % result[2] if result else "[---] "
                cases.append(case)
                entries.append(prefix + desc)

        model = self.test_case_list_model
        if cases == self._visible_cases:
            # Same rows: only update the text so the selection (and the editors) stay untouched
            for i, entry in enumerate(entries):
                if model.getElementAt(i) != entry:
                    model.setElementAt(entry, i)
        else:
            index = self.test_case_list_view.getSelectedIndex()
            previous = self._visible_cases[index] if 0 <= index < len(self._visible_cases) else None
            self._visible_cases = cases
            model.clear()
            for entry in entries:
                model.addElement(entry)
            if previous in cases:
                self.test_case_list_view.setSelectedIndex(cases.index(previous))

        if self.test_case_list_view.getSelectedIndex() < 0:
            if self._shown is not None:  # the case being viewed is gone from the list
                self._clear_editors()
        else:
            self._on_case_selected()  # picks up a result that just arrived; no-op when unchanged

    def _on_endpoint_selected(self):
        self.test_case_list_view.clearSelection()
        self._clear_editors()
        self._sync_checkboxes()
        self._update_test_case_list()
        self._update_test_button_state()

    def _on_case_selected(self):
        index = self.test_case_list_view.getSelectedIndex()
        label = self._current_label()
        if label is None or index < 0 or index >= len(self._visible_cases):
            return
        case = self._visible_cases[index]
        result = self._lookup_result(label, case)
        if not result:
            if self._shown is not None:
                self._clear_editors()
            return
        shown = self._shown
        if shown is not None and shown[0] == label and shown[1] == case and shown[2] is result:
            return  # already displayed, don't reset the editors (scroll position, selection)
        self._shown = (label, case, result)
        request_bytes, response_bytes, status, error = result
        message = self.endpoint_message_map.get(label)
        self.last_service = message.getHttpService() if message else None
        if error:
            request_bytes = request_bytes or _to_bytes("")
            response_bytes = _to_bytes("TypeXplorer error: " + _utf8(error))
        self.last_request = request_bytes or _to_bytes("")
        self.last_response = response_bytes or _to_bytes("")
        self._update_editors(self.last_request, self.last_response)

    def _clear_editors(self):
        empty = _to_bytes("")
        self._shown = None
        self.last_request = empty
        self.last_response = empty
        self.request_editor.setMessage(empty, True)
        self.response_editor.setMessage(empty, False)

    def _update_editors(self, request_bytes, response_bytes):
        self.request_editor.setMessage(request_bytes, True)
        self.response_editor.setMessage(response_bytes, False)

    # -- running tests ---------------------------------------------------------

    def _run_selected_tests(self):
        """Run all selected test cases for the current endpoint"""
        label = self._current_label()
        message = self.endpoint_message_map.get(label) if label else None
        selection = self.selected_cases.get(label) if label else None
        if message is None or not selection or self._unloaded.get():
            return
        if not self._running.compareAndSet(False, True):
            return  # a run is already in progress

        # Snapshot UI state here (on the UI thread) so the worker never touches Swing or live sets
        cases = [(h, b) for _, h, b in self.test_case_configs if (h, b) in selection]
        wrap_root = self.xml_root_wrapper_checkbox.isSelected()

        self.test_button.setEnabled(False)
        self.test_button.setText("Testing...")

        def run_tests_thread():
            try:
                for content_type, body_format in cases:
                    if self._unloaded.get() or Thread.currentThread().isInterrupted():
                        break
                    key = (content_type, body_format, wrap_root if body_format == "xml" else False)
                    with self._cache_lock:
                        results = self.test_results_cache.get(label)
                        if results is None:  # endpoint was deleted while running
                            break
                        cached = results.get(key)
                    if cached is not None and cached[2] != "ERR":  # failed runs are retried
                        continue
                    try:
                        result = self._execute_test_case(message, content_type, body_format, wrap_root)
                    except InterruptedException:
                        break  # extension unloaded mid-request
                    except ParseError as e:
                        result = (None, None, "ERR", "%s" % e)
                    except Exception as e:
                        self._callbacks.printError("TypeXplorer: %s" % traceback.format_exc())
                        result = (None, None, "ERR", "%s: %s" % (e.__class__.__name__, e))
                    with self._cache_lock:
                        results = self.test_results_cache.get(label)
                        if results is None:  # endpoint was deleted during the request
                            break
                        results[key] = result
                    SwingUtilities.invokeLater(self._update_test_case_list)
            finally:
                self._worker = None
                self._running.set(False)
                if not self._unloaded.get():
                    SwingUtilities.invokeLater(self._finish_run)

        worker = Thread(run_tests_thread, "TypeXplorer-tests")
        worker.setDaemon(True)
        self._worker = worker
        worker.start()

    def _finish_run(self):
        self.test_button.setText("Test Selected")
        self._update_test_button_state()
        self._update_test_case_list()

    def _execute_test_case(self, message, content_type, body_format, wrap_root):
        """Execute a single test case, returns (request, response, status, error)"""
        http_service, request_bytes = message.getHttpService(), message.getRequest()
        offset = self._helpers.analyzeRequest(request_bytes).getBodyOffset()
        raw = _to_str(request_bytes)
        head, body = raw[:offset], raw[offset:]
        lines = re.split(r'\r?\n', head.rstrip('\r\n'))
        request_line = lines[0]

        original_content_type = ""
        for header in lines[1:]:
            if header.lower().startswith("content-type:"):
                original_content_type = header.split(":", 1)[1].strip()
                break

        body = decode_body(body, lines[1:])
        params = parse_body(body, original_content_type)

        if body_format == 'urlencode':
            new_body = to_urlencode(params)
        elif body_format == 'json':
            new_body = to_json(params)
        elif body_format == 'xml':
            new_body = to_xml(params, wrap_root)
        elif body_format == 'multipart':
            boundary = "----WebKitFormBoundary" + uuid.uuid4().hex
            new_body = to_multipart(params, boundary)
            if content_type == 'multipart/form-data':
                content_type = 'multipart/form-data; boundary=%s' % boundary
        else:
            raise ParseError("unknown body format %r" % body_format)

        # These describe the old body or its transfer encoding, we set our own
        dropped = ("content-type:", "content-length:", "transfer-encoding:", "content-encoding:")
        new_headers = [request_line] + [h for h in lines[1:] if h and not h.lower().startswith(dropped)]
        new_headers.append('Content-Type: %s' % content_type)
        new_headers.append('Content-Length: %d' % len(new_body))

        new_request_bytes = _to_bytes('\r\n'.join(new_headers) + '\r\n\r\n' + new_body)
        http_response = self._make_http_request(http_service, new_request_bytes)
        response_bytes = http_response.getResponse() if http_response is not None else None
        if not response_bytes:
            return new_request_bytes, None, "ERR", "no response received (timeout or connection failure)"

        status = self._helpers.analyzeResponse(response_bytes).getStatusCode()
        return new_request_bytes, response_bytes, str(status), None

    def _make_http_request(self, http_service, request_bytes):
        """makeHttpRequest blocks on socket I/O that Thread.interrupt() can't break, so it runs on a
        helper thread while the caller waits interruptibly. Raises InterruptedException on unload."""
        task = FutureTask(_HttpCall(self._callbacks, http_service, request_bytes))
        sender = Thread(task, "TypeXplorer-http")
        sender.setDaemon(True)
        sender.start()
        try:
            return task.get()
        except InterruptedException:
            task.cancel(True)
            raise
        except ExecutionException as e:
            raise e.getCause()
