# -*- coding: utf-8 -*-
# JSCollector v2 - Burp Suite Extension (Improved)
# Collects all JavaScript files from in-scope targets and exports them locally.
# 
# Improvements over v1:
#   - Content-hash deduplication (skips JS with identical MD5 even from different URLs)
#   - Extracts inline <script> blocks from HTML responses
#   - Duplicate counter in stats bar
#   - Better export organization with separate folders for inline vs external scripts
#
# Installation:
#   1. Make sure Jython is configured in Burp: Extender > Options > Python Environment
#   2. Go to Extender > Extensions > Add
#   3. Set Extension Type: Python
#   4. Select this file
#
# Usage:
#   1. Add your target to scope (Target > Scope)
#   2. Browse the website normally (or use Spider/Crawler)
#   3. The extension auto-collects all .js responses AND inline scripts from HTML
#   4. Go to the "JS Collector v2" tab to see collected files
#   5. Set your export folder path and click "Export All JS Files"

from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory
from javax.swing import (
    JPanel, JButton, JLabel, JTextField, JScrollPane, JTable, JOptionPane,
    JFileChooser, BorderFactory, Box, BoxLayout, SwingConstants, JCheckBox,
    JSplitPane, JTextArea, SwingUtilities
)
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer
from javax.swing.border import EmptyBorder
from java.awt import BorderLayout, FlowLayout, Font, Color, Dimension, GridBagLayout, GridBagConstraints, Insets
from java.io import File
from java.net import URL
import os
import re
import hashlib
import threading
import time


class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("JS Collector v2")

        # Storage for collected JS files
        # { url_string: { 'url': ..., 'body': ..., 'size': ..., 'mime': ..., 'status': ..., 'source': ... } }
        self._js_files = {}
        self._lock = threading.Lock()

        # Content hash tracking for deduplication
        self._seen_hashes = {}  # { md5_hash: first_url_seen }
        self._dupe_count = 0     # how many duplicates were skipped
        self._inline_count = 0   # how many inline scripts extracted

        # Build UI on the Swing EDT
        SwingUtilities.invokeLater(self._buildUI)

        # Register as HTTP listener to passively capture JS
        callbacks.registerHttpListener(self)

        callbacks.printOutput("[JS Collector v2] Extension loaded successfully.")
        callbacks.printOutput("[JS Collector v2] Now captures external JS files AND inline <script> blocks.")
        callbacks.printOutput("[JS Collector v2] Content-hash deduplication enabled.")

    # ---------------------------------------------
    # UI Construction
    # ---------------------------------------------
    def _buildUI(self):
        self._panel = JPanel(BorderLayout(0, 10))
        self._panel.setBorder(EmptyBorder(10, 10, 10, 10))

        # -- Top control bar --
        topPanel = JPanel(BorderLayout(10, 0))
        topPanel.setBorder(BorderFactory.createTitledBorder("Export Settings"))

        pathPanel = JPanel(BorderLayout(5, 0))
        pathPanel.add(JLabel("Export Folder: "), BorderLayout.WEST)
        self._pathField = JTextField(os.path.join(os.path.expanduser("~"), "burp_js_export"))
        pathPanel.add(self._pathField, BorderLayout.CENTER)

        browseBtn = JButton("Browse...", actionPerformed=self._onBrowse)
        pathPanel.add(browseBtn, BorderLayout.EAST)
        topPanel.add(pathPanel, BorderLayout.CENTER)

        btnPanel = JPanel(FlowLayout(FlowLayout.RIGHT, 5, 5))

        self._beautifyCheck = JCheckBox("Beautify JS", True)
        btnPanel.add(self._beautifyCheck)

        self._flatCheck = JCheckBox("Flat filenames", False)
        self._flatCheck.setToolTipText("Save all files in one folder instead of preserving URL path structure")
        btnPanel.add(self._flatCheck)

        self._inlineCheck = JCheckBox("Capture inline scripts", True)
        self._inlineCheck.setToolTipText("Extract <script> blocks from HTML responses")
        btnPanel.add(self._inlineCheck)

        self._dedupCheck = JCheckBox("Deduplicate by content", True)
        self._dedupCheck.setToolTipText("Skip JS files with identical content (same MD5 hash)")
        btnPanel.add(self._dedupCheck)

        exportBtn = JButton("Export All JS Files", actionPerformed=self._onExport)
        exportBtn.setFont(Font("Dialog", Font.BOLD, 12))
        btnPanel.add(exportBtn)

        exportSelectedBtn = JButton("Export Selected", actionPerformed=self._onExportSelected)
        btnPanel.add(exportSelectedBtn)

        clearBtn = JButton("Clear All", actionPerformed=self._onClear)
        btnPanel.add(clearBtn)

        topPanel.add(btnPanel, BorderLayout.SOUTH)
        self._panel.add(topPanel, BorderLayout.NORTH)

        # -- Stats bar --
        self._statsLabel = JLabel("Collected: 0 JS files | 0 inline scripts | 0 duplicates skipped | 0 KB total")
        self._statsLabel.setFont(Font("Dialog", Font.PLAIN, 12))
        self._statsLabel.setBorder(EmptyBorder(5, 5, 5, 5))

        # -- Table of collected JS files --
        self._tableModel = JSTableModel()
        self._table = JTable(self._tableModel)
        self._table.setAutoCreateRowSorter(True)
        self._table.getColumnModel().getColumn(0).setPreferredWidth(50)   # #
        self._table.getColumnModel().getColumn(1).setPreferredWidth(450)  # URL
        self._table.getColumnModel().getColumn(2).setPreferredWidth(80)   # Size
        self._table.getColumnModel().getColumn(3).setPreferredWidth(60)   # Status
        self._table.getColumnModel().getColumn(4).setPreferredWidth(120)  # Content-Type
        self._table.getColumnModel().getColumn(5).setPreferredWidth(80)   # Source
        self._table.getColumnModel().getColumn(6).setPreferredWidth(180)  # Hash

        tableScroll = JScrollPane(self._table)

        # -- Preview pane --
        self._previewArea = JTextArea()
        self._previewArea.setEditable(False)
        self._previewArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._previewArea.setLineWrap(True)
        previewScroll = JScrollPane(self._previewArea)
        previewScroll.setPreferredSize(Dimension(0, 200))

        previewPanel = JPanel(BorderLayout())
        previewPanel.setBorder(BorderFactory.createTitledBorder("JS Preview (select a row)"))
        previewPanel.add(previewScroll, BorderLayout.CENTER)

        # Wire up table row selection for preview
        self._table.getSelectionModel().addListSelectionListener(self._onRowSelected)

        # Split pane: table on top, preview on bottom
        splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, previewPanel)
        splitPane.setResizeWeight(0.7)

        centerPanel = JPanel(BorderLayout())
        centerPanel.add(self._statsLabel, BorderLayout.NORTH)
        centerPanel.add(splitPane, BorderLayout.CENTER)

        self._panel.add(centerPanel, BorderLayout.CENTER)

        # Register the tab
        self._callbacks.addSuiteTab(self)

    # ---------------------------------------------
    # ITab
    # ---------------------------------------------
    def getTabCaption(self):
        return "JS Collector v2"

    def getUiComponent(self):
        return self._panel

    # ---------------------------------------------
    # IHttpListener - passively capture JS responses
    # ---------------------------------------------
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        httpService = messageInfo.getHttpService()
        requestInfo = self._helpers.analyzeRequest(messageInfo)
        url = requestInfo.getUrl()

        if not self._callbacks.isInScope(url):
            return

        response = messageInfo.getResponse()
        if response is None:
            return

        responseInfo = self._helpers.analyzeResponse(response)
        body = response[responseInfo.getBodyOffset():]
        bodyStr = self._helpers.bytesToString(body)

        if not bodyStr or len(bodyStr.strip()) == 0:
            return

        urlStr = str(url)
        statusCode = responseInfo.getStatusCode()

        # Get Content-Type
        contentType = "unknown"
        for header in responseInfo.getHeaders():
            if header.lower().startswith("content-type:"):
                contentType = header.split(":", 1)[1].strip()
                break

        # Check if this is a standalone JS file
        if self._isJavaScript(url, messageInfo):
            self._addJsFile(urlStr, bodyStr, statusCode, contentType, "external")

        # Check if this is HTML containing inline scripts
        if self._inlineCheck.isSelected() and self._isHTML(contentType):
            self._extractInlineScripts(urlStr, bodyStr, statusCode)

    def _isJavaScript(self, url, messageInfo):
        """Determine if a response is a JavaScript file."""
        urlStr = str(url).lower().split('?')[0].split('#')[0]

        if urlStr.endswith('.js') or urlStr.endswith('.mjs') or urlStr.endswith('.jsx'):
            return True

        response = messageInfo.getResponse()
        if response:
            responseInfo = self._helpers.analyzeResponse(response)
            for header in responseInfo.getHeaders():
                if header.lower().startswith("content-type:"):
                    ct = header.lower()
                    if any(t in ct for t in ['javascript', 'ecmascript', 'jscript']):
                        return True

        js_patterns = [
            r'/chunk-[a-f0-9]+',
            r'/bundle\.',
            r'/vendor\.',
            r'/app\.',
            r'/main\.',
            r'/runtime\.',
            r'\.chunk\.',
            r'/webpack',
        ]
        for pattern in js_patterns:
            if re.search(pattern, urlStr):
                if response:
                    responseInfo = self._helpers.analyzeResponse(response)
                    for header in responseInfo.getHeaders():
                        if header.lower().startswith("content-type:"):
                            ct = header.lower()
                            if 'html' in ct or 'css' in ct or 'image' in ct:
                                return False
                    return True

        return False

    def _isHTML(self, contentType):
        """Check if content type is HTML."""
        ct = contentType.lower()
        return 'html' in ct or 'xhtml' in ct

    def _extractInlineScripts(self, pageUrl, htmlBody, statusCode):
        """Extract all inline <script> blocks from an HTML response."""
        # Match <script> blocks - handles attributes, multiline content
        # Skips <script src="..."> (external scripts) and empty scripts
        pattern = re.compile(
            r'<script(?P<attrs>[^>]*)>(?P<body>.*?)</script>',
            re.DOTALL | re.IGNORECASE
        )

        script_index = 0
        for match in pattern.finditer(htmlBody):
            attrs = match.group('attrs')
            body = match.group('body').strip()

            # Skip external scripts (those with src attribute)
            if re.search(r'\bsrc\s*=', attrs, re.IGNORECASE):
                continue

            # Skip empty scripts
            if not body or len(body) < 10:
                continue

            # Skip JSON-LD and non-JS script types
            type_match = re.search(r'\btype\s*=\s*["\']([^"\']+)["\']', attrs, re.IGNORECASE)
            if type_match:
                script_type = type_match.group(1).lower().strip()
                # Allow javascript types, skip everything else
                js_types = ['text/javascript', 'application/javascript', 'module', '']
                if script_type not in js_types and 'javascript' not in script_type:
                    continue

            script_index += 1
            inline_key = "%s#inline_%d" % (pageUrl, script_index)

            self._addJsFile(
                inline_key,
                body,
                statusCode,
                "inline/javascript",
                "inline"
            )

        if script_index > 0:
            self._callbacks.printOutput(
                "[JS Collector v2] Extracted %d inline scripts from %s" % (script_index, pageUrl[:80])
            )

    def _addJsFile(self, urlStr, bodyStr, statusCode, contentType, source):
        """Add a JS file to the collection with content-hash deduplication."""
        contentHash = hashlib.md5(bodyStr.encode('utf-8', errors='replace')).hexdigest()

        with self._lock:
            # Content-hash deduplication
            if self._dedupCheck.isSelected() and contentHash in self._seen_hashes:
                existing_url = self._seen_hashes[contentHash]
                if existing_url != urlStr:
                    self._dupe_count += 1
                    self._callbacks.printOutput(
                        "[JS Collector v2] Skipped duplicate: %s (same as %s)" % (
                            urlStr[:80], existing_url[:80]
                        )
                    )
                    SwingUtilities.invokeLater(self._refreshTable)
                    return

            # Track this hash
            if contentHash not in self._seen_hashes:
                self._seen_hashes[contentHash] = urlStr

            # Track inline count
            if source == "inline":
                self._inline_count += 1

            self._js_files[urlStr] = {
                'url': urlStr,
                'body': bodyStr,
                'size': len(bodyStr),
                'status': statusCode,
                'content_type': contentType,
                'hash': contentHash,
                'source': source
            }

        SwingUtilities.invokeLater(self._refreshTable)

    # ---------------------------------------------
    # UI Event Handlers
    # ---------------------------------------------
    def _onBrowse(self, event):
        chooser = JFileChooser()
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        chooser.setDialogTitle("Select Export Folder")
        if chooser.showOpenDialog(self._panel) == JFileChooser.APPROVE_OPTION:
            self._pathField.setText(str(chooser.getSelectedFile().getAbsolutePath()))

    def _onExport(self, event):
        with self._lock:
            files = dict(self._js_files)

        if not files:
            JOptionPane.showMessageDialog(
                self._panel,
                "No JS files collected yet.\nBrowse your in-scope target first.",
                "Nothing to Export",
                JOptionPane.INFORMATION_MESSAGE
            )
            return

        self._exportFiles(files)

    def _onExportSelected(self, event):
        selectedRows = self._table.getSelectedRows()
        if not selectedRows:
            JOptionPane.showMessageDialog(
                self._panel, "No rows selected.",
                "Nothing Selected", JOptionPane.WARNING_MESSAGE
            )
            return

        with self._lock:
            allUrls = sorted(self._js_files.keys())
            files = {}
            for viewRow in selectedRows:
                modelRow = self._table.convertRowIndexToModel(viewRow)
                if modelRow < len(allUrls):
                    url = allUrls[modelRow]
                    files[url] = self._js_files[url]

        self._exportFiles(files)

    def _exportFiles(self, files):
        exportPath = self._pathField.getText().strip()
        if not exportPath:
            JOptionPane.showMessageDialog(
                self._panel, "Please set an export folder path.",
                "No Path", JOptionPane.WARNING_MESSAGE
            )
            return

        beautify = self._beautifyCheck.isSelected()
        flat = self._flatCheck.isSelected()

        def doExport():
            try:
                exported = 0
                errors = 0
                external_count = 0
                inline_count = 0

                for urlStr, data in files.items():
                    try:
                        source = data.get('source', 'external')

                        if flat:
                            if source == 'inline':
                                # For inline scripts, create a readable filename
                                filename = self._inlineToFlatFilename(urlStr)
                                filePath = os.path.join(exportPath, "inline", filename)
                            else:
                                filename = self._urlToFlatFilename(urlStr)
                                filePath = os.path.join(exportPath, "external", filename)
                        else:
                            if source == 'inline':
                                filePath = self._inlineToStructuredPath(exportPath, urlStr)
                            else:
                                filePath = self._urlToStructuredPath(exportPath, urlStr)

                        parentDir = os.path.dirname(filePath)
                        if not os.path.exists(parentDir):
                            os.makedirs(parentDir)

                        body = data['body']
                        if beautify:
                            body = self._simpleBeautify(body)

                        with open(filePath, 'w') as f:
                            f.write("// Source: %s\n" % urlStr)
                            f.write("// Type: %s script\n" % source)
                            f.write("// Collected by JS Collector v2 - Burp Suite Extension\n")
                            f.write("// Status: %s | Size: %s bytes | Hash: %s\n\n" % (
                                data['status'], data['size'], data['hash']
                            ))
                            f.write(body)

                        exported += 1
                        if source == 'inline':
                            inline_count += 1
                        else:
                            external_count += 1

                    except Exception as e:
                        errors += 1
                        self._callbacks.printError(
                            "[JS Collector v2] Error exporting %s: %s" % (urlStr, str(e))
                        )

                # Write manifest
                indexPath = os.path.join(exportPath, "_JS_INDEX.txt")
                with open(indexPath, 'w') as f:
                    f.write("JS Collector v2 Export Manifest\n")
                    f.write("=" * 60 + "\n")
                    f.write("Export Date: %s\n" % time.strftime("%Y-%m-%d %H:%M:%S"))
                    f.write("Total Files: %d (%d external, %d inline)\n" % (
                        len(files), external_count, inline_count
                    ))
                    with self._lock:
                        f.write("Duplicates Skipped: %d\n" % self._dupe_count)
                    f.write("=" * 60 + "\n\n")

                    f.write("--- EXTERNAL SCRIPTS ---\n\n")
                    for urlStr, data in sorted(files.items()):
                        if data.get('source') == 'external':
                            f.write("[%s] %s (%s bytes) %s\n" % (
                                data['status'], urlStr, data['size'], data['hash']
                            ))

                    f.write("\n--- INLINE SCRIPTS ---\n\n")
                    for urlStr, data in sorted(files.items()):
                        if data.get('source') == 'inline':
                            f.write("[%s] %s (%s bytes) %s\n" % (
                                data['status'], urlStr, data['size'], data['hash']
                            ))

                # Write URL list
                urlsPath = os.path.join(exportPath, "_JS_URLS.txt")
                with open(urlsPath, 'w') as f:
                    for urlStr in sorted(files.keys()):
                        f.write(urlStr + "\n")

                # Write hash dedup report
                dedupPath = os.path.join(exportPath, "_DEDUP_REPORT.txt")
                with open(dedupPath, 'w') as f:
                    f.write("Content Deduplication Report\n")
                    f.write("=" * 60 + "\n\n")
                    with self._lock:
                        f.write("Unique content hashes: %d\n" % len(self._seen_hashes))
                        f.write("Duplicates skipped: %d\n\n" % self._dupe_count)
                        for h, url in sorted(self._seen_hashes.items(), key=lambda x: x[1]):
                            f.write("%s  %s\n" % (h, url[:120]))

                # Write grep-ready search script
                searchPath = os.path.join(exportPath, "search.sh")
                with open(searchPath, 'w') as f:
                    f.write("#!/bin/bash\n")
                    f.write("# Quick search helper for JS Collector v2 export\n")
                    f.write("# Usage: ./search.sh <pattern>\n")
                    f.write('# Example: ./search.sh "isFacebookURI"\n')
                    f.write('# Example: ./search.sh "innerHTML"\n')
                    f.write('# Example: ./search.sh "postMessage"\n\n')
                    f.write('EXPORT_DIR="%s"\n\n' % exportPath)
                    f.write('if [ -z "$1" ]; then\n')
                    f.write('    echo "Usage: ./search.sh <pattern>"\n')
                    f.write('    echo ""\n')
                    f.write('    echo "Useful bug bounty searches:"\n')
                    f.write('    echo "  ./search.sh innerHTML"\n')
                    f.write('    echo "  ./search.sh eval"\n')
                    f.write('    echo "  ./search.sh document.write"\n')
                    f.write('    echo "  ./search.sh postMessage"\n')
                    f.write('    echo "  ./search.sh location.href"\n')
                    f.write('    echo "  ./search.sh dangerouslySetInnerHTML"\n')
                    f.write('    echo "  ./search.sh isFacebookURI"\n')
                    f.write('    echo "  ./search.sh window.open"\n')
                    f.write('    echo "  ./search.sh \\.html\\("\n')
                    f.write('    echo "  ./search.sh fromCharCode"\n')
                    f.write('    exit 1\n')
                    f.write('fi\n\n')
                    f.write('echo "Searching for: $1"\n')
                    f.write('echo "========================================"\n')
                    f.write('grep -rn --include="*.js" "$1" "$EXPORT_DIR" | head -200\n')
                    f.write('echo "========================================"\n')
                    f.write('echo "Total matches:"\n')
                    f.write('grep -rn --include="*.js" "$1" "$EXPORT_DIR" | wc -l\n')
                os.chmod(searchPath, 0o755)

                msg = "Exported %d JS files to:\n%s\n\n" % (exported, exportPath)
                msg += "  External scripts: %d\n" % external_count
                msg += "  Inline scripts: %d\n" % inline_count
                if errors > 0:
                    msg += "\n%d files had errors (check Extender output)." % errors
                msg += "\n\nAlso created:\n"
                msg += "- _JS_INDEX.txt (manifest)\n"
                msg += "- _JS_URLS.txt (URL list)\n"
                msg += "- _DEDUP_REPORT.txt (hash dedup report)\n"
                msg += "- search.sh (grep helper script)"

                JOptionPane.showMessageDialog(
                    self._panel, msg, "Export Complete",
                    JOptionPane.INFORMATION_MESSAGE
                )

            except Exception as e:
                JOptionPane.showMessageDialog(
                    self._panel, "Export failed: %s" % str(e),
                    "Error", JOptionPane.ERROR_MESSAGE
                )

        threading.Thread(target=doExport).start()

    def _onClear(self, event):
        result = JOptionPane.showConfirmDialog(
            self._panel, "Clear all collected JS files and hash history?",
            "Confirm Clear", JOptionPane.YES_NO_OPTION
        )
        if result == JOptionPane.YES_OPTION:
            with self._lock:
                self._js_files.clear()
                self._seen_hashes.clear()
                self._dupe_count = 0
                self._inline_count = 0
            SwingUtilities.invokeLater(self._refreshTable)

    def _onRowSelected(self, event):
        if event.getValueIsAdjusting():
            return
        row = self._table.getSelectedRow()
        if row < 0:
            self._previewArea.setText("")
            return

        modelRow = self._table.convertRowIndexToModel(row)
        with self._lock:
            urls = sorted(self._js_files.keys())
            if modelRow < len(urls):
                data = self._js_files[urls[modelRow]]
                preview = data['body'][:10240]
                if len(data['body']) > 10240:
                    preview += "\n\n... [truncated - %d bytes total] ..." % data['size']
                self._previewArea.setText(preview)
                self._previewArea.setCaretPosition(0)

    # ---------------------------------------------
    # Table refresh
    # ---------------------------------------------
    def _refreshTable(self):
        with self._lock:
            rows = []
            for idx, url in enumerate(sorted(self._js_files.keys())):
                d = self._js_files[url]
                rows.append([
                    idx + 1,
                    d['url'],
                    self._formatSize(d['size']),
                    d['status'],
                    d['content_type'],
                    d.get('source', 'external'),
                    d['hash']
                ])
            totalSize = sum(d['size'] for d in self._js_files.values())
            dupes = self._dupe_count
            inlines = self._inline_count
            external = len(self._js_files) - inlines

        self._tableModel.setData(rows)
        self._statsLabel.setText(
            "Collected: %d JS files (%d external, %d inline) | %d duplicates skipped | %s total" % (
                len(rows), external, inlines, dupes, self._formatSize(totalSize)
            )
        )

    # ---------------------------------------------
    # Utility methods
    # ---------------------------------------------
    def _urlToFlatFilename(self, urlStr):
        try:
            u = URL(urlStr)
            host = u.getHost() or "unknown"
            path = u.getPath() or "/unknown.js"
            name = path.split('/')[-1] or "index.js"
            if not name.endswith('.js'):
                name += '.js'
            safe = re.sub(r'[^\w.\-]', '_', "%s__%s" % (host, name))
            return safe
        except:
            return re.sub(r'[^\w.\-]', '_', urlStr)[:200] + '.js'

    def _inlineToFlatFilename(self, urlStr):
        """Convert an inline script key to a flat filename."""
        try:
            # urlStr format: "https://www.facebook.com/page#inline_3"
            parts = urlStr.rsplit('#', 1)
            base_url = parts[0]
            inline_id = parts[1] if len(parts) > 1 else "inline_0"

            u = URL(base_url)
            host = u.getHost() or "unknown"
            path = u.getPath() or "/"
            page = path.split('/')[-1] or "index"
            page = re.sub(r'[^\w.\-]', '_', page)

            return "%s__%s__%s.js" % (host, page, inline_id)
        except:
            return re.sub(r'[^\w.\-]', '_', urlStr)[:200] + '.js'

    def _urlToStructuredPath(self, basePath, urlStr):
        try:
            u = URL(urlStr)
            host = u.getHost() or "unknown"
            path = u.getPath() or "/unknown.js"
            path = path.lstrip('/')
            if not path:
                path = "index.js"
            if not path.endswith('.js'):
                path += '.js'
            parts = path.split('/')
            parts = [re.sub(r'[^\w.\-]', '_', p) for p in parts]
            return os.path.join(basePath, "external", host, *parts)
        except:
            safe = re.sub(r'[^\w.\-]', '_', urlStr)[:200] + '.js'
            return os.path.join(basePath, "external", safe)

    def _inlineToStructuredPath(self, basePath, urlStr):
        """Create a structured path for inline scripts."""
        try:
            parts = urlStr.rsplit('#', 1)
            base_url = parts[0]
            inline_id = parts[1] if len(parts) > 1 else "inline_0"

            u = URL(base_url)
            host = u.getHost() or "unknown"
            path = u.getPath() or "/"
            path = path.lstrip('/') or "index"

            # Sanitize path components
            path_parts = path.split('/')
            path_parts = [re.sub(r'[^\w.\-]', '_', p) for p in path_parts]

            # Last part becomes the directory, inline_id becomes the filename
            filename = "%s.js" % inline_id

            return os.path.join(basePath, "inline", host, *(path_parts + [filename]))
        except:
            safe = re.sub(r'[^\w.\-]', '_', urlStr)[:200] + '.js'
            return os.path.join(basePath, "inline", safe)

    def _simpleBeautify(self, js):
        """Basic JS beautification without external dependencies."""
        result = js

        lines = result.split('\n')
        if len(lines) > 5:
            avg_len = sum(len(l) for l in lines[:20]) / min(len(lines), 20)
            if avg_len < 200:
                return result

        result = re.sub(r';(\s*)', ';\n', result)
        result = re.sub(r'\{(\s*)', '{\n', result)
        result = re.sub(r'\}(\s*)', '\n}\n', result)
        result = re.sub(r'\n{3,}', '\n\n', result)

        return result

    def _formatSize(self, size):
        if size < 1024:
            return "%d B" % size
        elif size < 1024 * 1024:
            return "%.1f KB" % (size / 1024.0)
        else:
            return "%.1f MB" % (size / (1024.0 * 1024.0))


class JSTableModel(AbstractTableModel):
    """Table model for the JS files list."""

    COLUMNS = ["#", "URL", "Size", "Status", "Content-Type", "Source", "MD5 Hash"]

    def __init__(self):
        self._data = []

    def setData(self, data):
        self._data = data
        self.fireTableDataChanged()

    def getRowCount(self):
        return len(self._data)

    def getColumnCount(self):
        return len(self.COLUMNS)

    def getColumnName(self, col):
        return self.COLUMNS[col]

    def getValueAt(self, row, col):
        if row < len(self._data):
            return self._data[row][col]
        return ""

    def getColumnClass(self, col):
        if col == 0:
            from java.lang import Integer
            return Integer
        if col == 3:
            from java.lang import Integer
            return Integer
        from java.lang import String
        return String
