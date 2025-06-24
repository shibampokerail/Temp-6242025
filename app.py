# GUI that uses the SecurityTools.py for Qualys Tagging operations
# Status: In Progress
# Note To Reviewer: Documentation is inconsistent. Currently working on that.

import sys
import logging
from PySide6.QtCore import Qt, QThread, Signal, QObject, Slot, QTimer,QStringListModel
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QTabWidget, QTableWidget,
    QTableWidgetItem, QHeaderView, QTextEdit, QFileDialog, QMessageBox,QComboBox, QDialog, QDialogButtonBox, QCompleter, QScrollArea, QDialog
)

from logging_config import setup_logging
from SecurityTools import QualysAPI, QualysAPIError
import functools




class LoginDialog(QDialog):
    """A dialog to get user credentials and test the API connection."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Qualys API Login")
        self.setModal(True)

        self.api_client = None

        self.api_url = "https://qualysapi.qualys.com"

        layout = QVBoxLayout(self)

        self.username_entry = QLineEdit()
        self.password_entry = QLineEdit()
        self.password_entry.setEchoMode(QLineEdit.Password)

        layout.addWidget(QLabel("Qualys Username:"))
        layout.addWidget(self.username_entry)
        layout.addWidget(QLabel("Password:"))
        layout.addWidget(self.password_entry)

        self.username_entry.setFocus()

        self.status_label = QLabel("Please enter your credentials.")
        self.status_label.setStyleSheet("color: grey;")
        layout.addWidget(self.status_label)

        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.button(QDialogButtonBox.Ok).setText("Connect")
        self.button_box.accepted.connect(self.attempt_connection)
        self.button_box.rejected.connect(self.reject)
        layout.addWidget(self.button_box)

    def attempt_connection(self):
        """Called when the 'Connect' button is clicked."""
        user = self.username_entry.text()
        pwd = self.password_entry.text()

        if not all([user, pwd]):
            self.status_label.setText("Username and Password are required.")
            self.status_label.setStyleSheet("color: red;")
            return

        self.status_label.setText("Connecting...")
        self.status_label.setStyleSheet("color: orange;")
        self.button_box.setEnabled(False)
        QApplication.processEvents()

        try:
            temp_client = QualysAPI(self.api_url, user, pwd)
            success, message = temp_client.test_connection()

            if success:
                self.api_client = temp_client
                self.accept()
            else:
                raise QualysAPIError(message)

        except Exception as e:
            self.status_label.setText(f"Failed: {e}")
            self.status_label.setStyleSheet("color: red;")
            self.button_box.setEnabled(True)
class Worker(QObject):
    """
    A worker object that runs in a separate thread.
    Emits signals to communicate results or errors back to the main GUI thread.
    """
    finished = Signal(object)
    error = Signal(str)
    progress = Signal(str)

    def __init__(self, target, *args, **kwargs):
        super().__init__()
        self.target = target
        self.args = args
        self.kwargs = kwargs # Store the keyword arguments

    def run(self):
        """The function that will be executed in the new thread."""
        try:
            logging.info(f"Worker starting task: {self.target.__name__}")
            result = self.target(*self.args, **self.kwargs)
            self.finished.emit(result)
        except Exception as e:
            logging.error(f"Worker thread caught an exception: {e}")
            self.error.emit(str(e))


class TagManagerDialog(QDialog):
    def __init__(self, asset_id, asset_ip, current_tags, all_tags_model, all_valid_tags, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Manage Tags for {asset_ip} (ID: {asset_id})")
        self.setMinimumSize(500, 600)

        
        self.original_tags = set(current_tags)
        self.tags_to_add = set()
        self.tags_to_remove = set()

    
        self.all_valid_tags_set = set(all_valid_tags)

        # Main layout of the GUI
        self.main_layout = QVBoxLayout(self)

  
        self.main_layout.addWidget(QLabel("<b>Current Tags on Asset:</b>"))
        scroll_area = QScrollArea(self)
        scroll_area.setWidgetResizable(True)
        self.tags_container = QWidget()
        self.tags_layout = QVBoxLayout(self.tags_container)
        self.tags_layout.setAlignment(Qt.AlignTop)
        scroll_area.setWidget(self.tags_container)
        self.main_layout.addWidget(scroll_area)


        self.main_layout.addWidget(QLabel("<b>Add New Tag:</b>"))
        add_group_layout = QHBoxLayout()
        self.add_tag_entry = QLineEdit()
        self.add_tag_entry.setPlaceholderText("Type to find a tag to add...")

        self.tag_completer = CustomTagCompleter(self)
        self.tag_completer.setCaseSensitivity(Qt.CaseInsensitive)
        self.tag_completer.setModel(all_tags_model)
        self.tag_completer.search_entry = self.add_tag_entry
        self.add_tag_entry.setCompleter(self.tag_completer)


        self.add_tag_button = QPushButton("➕ Stage for Addition")

        add_group_layout.addWidget(self.add_tag_entry)
        add_group_layout.addWidget(self.add_tag_button)
        self.main_layout.addLayout(add_group_layout)

  
        self.main_layout.addWidget(QLabel("<b>Staged Changes:</b>"))
        self.changes_log = QTextEdit()
        self.changes_log.setReadOnly(True)
        self.changes_log.setMaximumHeight(150)
        self.main_layout.addWidget(self.changes_log)

        self.button_box = QDialogButtonBox()
        self.save_button = self.button_box.addButton("Save Changes", QDialogButtonBox.AcceptRole)
        self.cancel_button = self.button_box.addButton("Cancel", QDialogButtonBox.RejectRole)
        self.main_layout.addWidget(self.button_box)

        self.save_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)
        self.add_tag_button.clicked.connect(self.stage_tag_for_addition)
        self.add_tag_entry.returnPressed.connect(self.stage_tag_for_addition)

        self.populate_current_tags()
        self.update_ui_state()

    def update_ui_state(self):
        """
        Updates the staged changes log and enables/disables the Save button.
        """
     
        self.changes_log.clear()
        log_html = ""
        for tag in sorted(list(self.tags_to_add)):
            log_html += f'<p style="color:green;"><b>ADD:</b> {tag}</p>'
        for tag in sorted(list(self.tags_to_remove)):
            log_html += f'<p style="color:red;"><b>REMOVE:</b> {tag}</p>'

        if not log_html:
            log_html = '<p style="color:grey;"><i>No changes staged.</i></p>'

        self.changes_log.setHtml(log_html)

        
        has_changes = bool(self.tags_to_add or self.tags_to_remove)
        self.save_button.setEnabled(has_changes)

    def populate_current_tags(self):
        """Populates the list of tags currently on the asset."""
     
        while self.tags_layout.count():
            child = self.tags_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        for tag_name in sorted(list(self.original_tags)):
            widget = QWidget()
            layout = QHBoxLayout(widget)
            layout.setContentsMargins(0, 0, 0, 0)

            label = QLabel(tag_name)
            remove_button = QPushButton("❌ Remove Tag")
            remove_button.setToolTip(f"Stage '{tag_name}' for removal")

 
            remove_button.clicked.connect(functools.partial(self.stage_tag_for_removal, tag_name))

            layout.addWidget(label)
            layout.addStretch()
            layout.addWidget(remove_button)
            self.tags_layout.addWidget(widget)

    def stage_tag_for_addition(self):
        """Handles the logic for staging a new tag to be added, with validation."""
        tag_to_add = self.add_tag_entry.text().strip()
        if not tag_to_add:
            return

     
        if tag_to_add not in self.all_valid_tags_set:
            QMessageBox.critical(self, "Invalid Tag",
                                 f"The tag '{tag_to_add}' does not exist in Qualys.\n\n"
                                 "Please select a valid tag from the auto-completion list.")
            return

        
        if tag_to_add in self.original_tags:
            QMessageBox.warning(self, "Tag Exists", f"The tag '{tag_to_add}' is already on this asset.")
            return

      
        if tag_to_add in self.tags_to_add:
            QMessageBox.information(self, "Already Staged", f"The tag '{tag_to_add}' is already staged for addition.")
            return

        if tag_to_add in self.tags_to_remove:
            self.tags_to_remove.remove(tag_to_add)
        else:
            self.tags_to_add.add(tag_to_add)

        self.add_tag_entry.clear()
        self.update_ui_state()

    def stage_tag_for_removal(self, tag_name):
        """Handles the logic for staging an existing tag to be removed."""
      
        if tag_name in self.original_tags:
            self.tags_to_remove.add(tag_name)

        if tag_name in self.tags_to_add:
            self.tags_to_add.remove(tag_name)

        sender_button = self.sender()
        if sender_button:
            sender_button.setEnabled(False)
            sender_button.setText("Staged")

        self.update_ui_state()

    def get_changes(self):
        """Returns the final sets of tags to be added and removed."""
        return list(self.tags_to_add), list(self.tags_to_remove)

class CustomTagCompleter(QCompleter):
    """
    A custom QCompleter that understands our AND (+) and OR (,) syntax.
    It provides suggestions based on the last typed term after a separator.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setCompletionRole(Qt.DisplayRole)

    def splitPath(self, path):
        """
        Overrides the default behavior to split the text by our custom separators.
        This tells the completer which part of the string to work on.
        """
        last_plus = path.rfind('+')
        last_comma = path.rfind(',')

    
        separator_pos = max(last_plus, last_comma)

        if separator_pos == -1:
      
            return [path]
        else:

            return [path[separator_pos + 1:].lstrip()]

    def pathFromIndex(self, index):
        """
        Overrides the default behavior for when a user selects a suggestion.
        This replaces the last typed term with the full suggestion.
        """
        path = self.search_entry.text()  

        last_plus = path.rfind('+')
        last_comma = path.rfind(',')
        separator_pos = max(last_plus, last_comma)

        if separator_pos == -1:
            return index.data()  
        else:
      
            prefix = path[:separator_pos + 1]
       
            if not prefix.endswith(' '):
                prefix += ' '
            return prefix + index.data()

class QualysDashboardApp(QMainWindow):
    show_error_signal = Signal(str, str)

    def __init__(self, api_client):
        super().__init__()
        self.setWindowTitle("Qualys Device & Tag Dashboard")
        self.setGeometry(100, 100, 1200, 750)

        self.api_client = api_client
        self.thread = None

        self.asset_cache = []

        self.search_timer = QTimer(self)
        self.search_timer.setSingleShot(True)
        self.search_timer.setInterval(300)
        self.search_timer.timeout.connect(self.perform_local_asset_search)

        self.tag_completer = CustomTagCompleter(self)
        self.tag_completer.setCaseSensitivity(Qt.CaseInsensitive)
        self.tag_completer.setFilterMode(Qt.MatchContains) # This is key: it finds matches anywhere in the string


        self.show_error_signal.connect(self.show_error_messagebox)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        self.status_label = QLabel("Status: Connected. Please fetch assets to begin searching.")
        self.status_label.setStyleSheet("color: orange;")
        main_layout.addWidget(self.status_label)

        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        self.create_query_tab()
        self.create_single_tagging_tab()
        self.create_bulk_tagging_tab()
        self.create_settings_tab()

        self.set_buttons_enabled(False)


    @Slot(str, str)
    def show_error_messagebox(self, title, message):
        """A dedicated, safe slot to show critical error messages."""
        QMessageBox.critical(self, title, message)


    def _split_at_top_level(self, query, delimiter):
        """
        A helper that splits a string by a delimiter, but respects parentheses.
        Example: "(a, b) + c" split by '+' -> ["(a, b)", "c"]
        """
        parts = []
        balance = 0
        last_split = 0
        for i, char in enumerate(query):
            if char == '(':
                balance += 1
            elif char == ')':
                balance -= 1
            elif char == delimiter and balance == 0:
                parts.append(query[last_split:i].strip())
                last_split = i + 1
        parts.append(query[last_split:].strip())
        return parts

    def _evaluate_tag_query(self, query, asset_tags_lower):
        """
        Recursively evaluates a tag query string against a set of an asset's tags.
        """
        query = query.strip()

        if not query:
            return False

        # Handles OR operations (,) at the lowest precedence
        or_parts = self._split_at_top_level(query, ',')
        if len(or_parts) > 1:
            # If any parts of the expression is true, the whole thing is true similarly below
            return any(self._evaluate_tag_query(part, asset_tags_lower) for part in or_parts)

        # Handle AND operand (+) at the next precedence
        and_parts = self._split_at_top_level(query, '+')
        if len(and_parts) > 1:
          
            return all(self._evaluate_tag_query(part, asset_tags_lower) for part in and_parts)

        # Handles NOT operator (-) and single terms at the highest precedence
        #---------------------------------------------------------------------------------------------------------ReqiuiresFix: Does not work with parantheses currently
        if query.startswith('-'):
            # Evaluates the expression after the '-' and return the opposite
            term = query[1:].strip()
            return not self._evaluate_tag_query(term, asset_tags_lower)

        # This Handles parentheses
        if query.startswith('(') and query.endswith(')'):
            # This evaluates the expression inside the parentheses
            return self._evaluate_tag_query(query[1:-1], asset_tags_lower)

      
        return query in asset_tags_lower
    def create_query_tab(self):
        """
        Creates the main query tab with a unified, live filter and tag auto-completion.
        """
        tab = QWidget()
        layout = QVBoxLayout(tab)
        self.tabs.addTab(tab, "Query")

        fetch_frame = QHBoxLayout()
        self.fetch_assets_button = QPushButton("🔄 Refresh All Assets")
        fetch_frame.addWidget(self.fetch_assets_button)
        fetch_frame.addStretch()
        layout.addLayout(fetch_frame)

        query_frame = QHBoxLayout()
        query_frame.addWidget(QLabel("Filter Assets By:"))

        self.query_type_combo = QComboBox()
        self.query_type_combo.addItems(["IP Address", "Hostname", "Tags"])
        self.query_type_combo.setFixedWidth(120)
        query_frame.addWidget(self.query_type_combo)

        self.search_entry = QLineEdit()
        self.search_entry.setPlaceholderText("Type to filter... ")

        self.search_entry.setCompleter(self.tag_completer)

        self.tag_completer.search_entry = self.search_entry

        query_frame.addWidget(self.search_entry)
        layout.addLayout(query_frame)

        self.query_type_combo.setEnabled(False)
        self.search_entry.setEnabled(False)

        self.results_table = QTableWidget()
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.results_table.setSortingEnabled(True)
        self.results_table.cellDoubleClicked.connect(self.show_tag_manager)
        layout.addWidget(self.results_table)

        self.fetch_assets_button.clicked.connect(self.start_fetch_assets_cache)
        self.search_entry.textChanged.connect(self.on_search_text_changed)
        self.query_type_combo.currentIndexChanged.connect(self.on_search_text_changed)

    def start_fetch_assets_cache(self):
        """Starts a background thread to fetch assets and build the cache."""
        self.set_buttons_enabled(False)
        self.status_label.setText("Status: Fetching all assets... This may take a moment.")
        self.status_label.setStyleSheet("color: orange;")

        def on_finish(assets):
            self.asset_cache = assets

           
            unique_tags = set()
            for asset in self.asset_cache:
                for tag_name in asset.get('tags', []):
                    unique_tags.add(tag_name)

            tag_list = sorted(list(unique_tags), key=str.lower)
            self.tag_list_model = QStringListModel(tag_list)
            self.tag_completer.setModel(self.tag_list_model)
           

            self.status_label.setText(
                f"Status: Cache built with {len(assets)} assets and {len(tag_list)} unique tags. Ready to search."
            )
            self.status_label.setStyleSheet("color: green;")

            self.query_type_combo.setEnabled(True)
            self.search_entry.setEnabled(True)
            self.set_buttons_enabled(True)
            self.perform_local_asset_search()

        on_error = lambda e: self.handle_api_error(e, "Asset Fetch Error")
        self.run_in_thread(self.api_client.get_all_assets_for_cache, on_finish, on_error)


    def on_search_text_changed(self):
        """
        This slot is called on every text or dropdown change.
        It enables/disables the completer and starts the search timer.
        """
        # Enable the completer ONLY if the user is searching for tags
        if self.query_type_combo.currentText() == "Tags":
            self.search_entry.setCompleter(self.tag_completer)
        else:
            self.search_entry.setCompleter(None)

            # Start the debounce timer for the live table filter
        self.search_timer.start()


    @Slot(int, int)
    def show_tag_manager(self, row, column):
        """
        Triggered on table double-click. Shows the TagManagerDialog for the selected asset.
        """
        logging.info("--- show_tag_manager called ---")
        id_item = self.results_table.item(row, 0)
        if not id_item:
            logging.warning("Double-clicked cell has no ID item. Aborting.")
            return

        asset_id = id_item.text()
        logging.info(f"Attempting to manage tags for asset ID: {asset_id}")

        target_asset = next((asset for asset in self.asset_cache if asset['id'] == asset_id), None)

        if not target_asset:
            logging.error(f"Could not find asset ID {asset_id} in the local cache!")
            self.show_error_signal.emit("Error", f"Could not find asset with ID {asset_id} in the cache.")
            return
        logging.info(f"Found asset in cache: IP={target_asset['ip']}, Hostname={target_asset['hostname']}")

        all_valid_tags = self.tag_list_model.stringList()

        dialog = TagManagerDialog(
            asset_id=target_asset['id'],
            asset_ip=target_asset['ip'],
            current_tags=target_asset['tags'],
            all_tags_model=self.tag_list_model,
            all_valid_tags=all_valid_tags,
            parent=self
        )

        # The .exec() call blocks until the dialog is closed
        result = dialog.exec()

        if result == QDialog.Accepted:
            logging.info("TagManagerDialog was accepted (Save Changes clicked).")
            add_tags, remove_tags = dialog.get_changes()
            logging.info(f"Changes returned from dialog: ADD={add_tags}, REMOVE={remove_tags}")

            if not add_tags and not remove_tags:
                logging.info("No actual changes to apply. Skipping API call.")
                self.update_status("No tag changes to apply.", "green")
                return

            logging.info("Proceeding to call start_update_asset_tags...")
        
            self.start_update_asset_tags(asset_id, add_tags, remove_tags)
        else:
            logging.info("TagManagerDialog was rejected (Cancel clicked or closed). No action taken.")


    def start_update_asset_tags(self, asset_id, add_tags, remove_tags):
        """
        Calls the API in a background thread to update tags for a single asset
        and provides feedback in the UI.
        This function DEFINITELY accepts asset_id, add_tags, and remove_tags.
        """
        logging.info("--- start_update_asset_tags called ---")
        logging.info(f"  - asset_id: {asset_id} (type: {type(asset_id)})")
        logging.info(f"  - add_tags: {add_tags} (type: {type(add_tags)})")
        logging.info(f"  - remove_tags: {remove_tags} (type: {type(remove_tags)})")

        self.set_buttons_enabled(False)
        log_msg = f"Staging API call for asset {asset_id}: ADD={add_tags}, REMOVE={remove_tags}"

        self.update_status(f"Updating tags for asset {asset_id}...", "yellow")
        self.single_tag_log.append(log_msg)

        def on_finish(result):
            logging.info(f"Tag update for asset {asset_id} finished successfully in worker thread.")
            success_msg = f"SUCCESS: {result}\n"
            self.single_tag_log.append(success_msg)
            self.update_status("Tags updated successfully. Refresh cache to see changes.", "green")

            QMessageBox.information(self, "Success",
                                    "Tags updated successfully on the Qualys server.\n\n"
                                    "Click 'Refresh All Assets' to see the changes in this application.")
            self.set_buttons_enabled(True)

        def on_error(error):
            logging.error(f"Tag update for asset {asset_id} failed in worker thread: {error}")
            error_msg = f"ERROR: {error}\n"
            self.single_tag_log.append(error_msg)
            self.handle_api_error(error, "Tag Update Error")

        logging.info("Starting background worker thread for API call...")
       
        self.run_in_thread(
            self.api_client.update_asset_tags,
            on_finish,
            on_error,
            asset_id,
            add_tags,
            remove_tags
        )

    @Slot()
    def perform_local_asset_search(self):
        """
        Performs a unified search on the asset cache using the advanced query parser for tags.
        """
        if not self.asset_cache:
            return

        criteria = self.search_entry.text().strip()
        search_type = self.query_type_combo.currentText()

        if not criteria:
            self.populate_table(self.asset_cache, ['id', 'ip', 'hostname', 'tags'])
            return

        
        for asset in self.asset_cache:
            asset['tags_lower'] = {tag.lower() for tag in asset['tags']}

        results = []

        if search_type == "Tags":
            
            query_lower = criteria.lower()
            results = [
                asset for asset in self.asset_cache
                if self._evaluate_tag_query(query_lower, asset['tags_lower'])
            ]
        else:  
            criteria_lower = criteria.lower()
            if search_type == "IP Address":
                results = [
                    asset for asset in self.asset_cache
                    if criteria_lower in asset['ip']
                ]
            elif search_type == "Hostname":
                results = [
                    asset for asset in self.asset_cache
                    if criteria_lower in asset['hostname_lower']
                ]

        self.populate_table(results, ['id', 'ip', 'hostname', 'tags'])

    def populate_table(self, data, headers):
        """
        Populates the results table with the given data and headers.
        Includes word wrapping and intelligent column resizing for better visual layout.
        """
        self.results_table.setUpdatesEnabled(False)

        try:

            self.results_table.setWordWrap(True)

            self.results_table.setRowCount(0)
            if not data:
            
                self.results_table.setUpdatesEnabled(True)
                return

            self.results_table.setRowCount(len(data))
            self.results_table.setColumnCount(len(headers))
            self.results_table.setHorizontalHeaderLabels([h.upper() for h in headers])

            for row_index, row_data in enumerate(data):
                for col_index, header in enumerate(headers):
                    item_value = row_data.get(header, '')

                    if isinstance(item_value, list):
                        item_text = ', '.join(item_value)
                    else:
                        item_text = str(item_value)

                    table_item = QTableWidgetItem(item_text)

                 
                    if header == 'tags' and len(item_text) > 50:  # Only for long tag lists
                        table_item.setToolTip(item_text)

                    self.results_table.setItem(row_index, col_index, table_item)

      
            header_view = self.results_table.horizontalHeader()

            if 'id' in headers:
                header_view.setSectionResizeMode(headers.index('id'), QHeaderView.ResizeToContents)
            if 'ip' in headers:
                header_view.setSectionResizeMode(headers.index('ip'), QHeaderView.ResizeToContents)

          
            if 'hostname' in headers:
                header_view.setSectionResizeMode(headers.index('hostname'), QHeaderView.Interactive)
                self.results_table.resizeColumnToContents(headers.index('hostname'))

          
            if 'tags' in headers:
                header_view.setSectionResizeMode(headers.index('tags'), QHeaderView.Stretch)

            # --- VISUAL: After setting column widths, resize rows to fit wrapped text ---
            self.results_table.resizeRowsToContents()

        finally:
            # --- PERFORMANCE: Re-enable table redrawing to show the result all at once ---
            self.results_table.setUpdatesEnabled(True)

    def perform_local_search(self):
        """Performs a search on the in-memory asset cache. This is very fast."""
        if not self.asset_cache:
            self.show_error_signal.emit("Cache Empty", "Please fetch assets before searching.")
            return

        criteria = self.search_entry.text().strip()
        search_type = self.query_type_combo.currentText()

        if not criteria:
            # If search is empty, show all cached assets
            self.populate_table(self.asset_cache, ['id', 'ip', 'hostname', 'tags'])
            return

        criteria_lower = criteria.lower()
        results = []

        if search_type == "IP Address":
            results = [
                asset for asset in self.asset_cache
                if criteria_lower in asset['ip']
            ]
        elif search_type == "Hostname":
            results = [
                asset for asset in self.asset_cache
                if criteria_lower in asset['hostname_lower']
            ]

        self.populate_table(results, ['id', 'ip', 'hostname', 'tags'])

    def create_single_tagging_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        self.tabs.addTab(tab, "Single Tagging")

        asset_id_layout = QHBoxLayout()
        asset_id_layout.addWidget(QLabel("Asset ID:"))
        self.asset_id_entry = QLineEdit()
        self.asset_id_entry.setPlaceholderText("Enter the numeric Asset ID from a device query")
        asset_id_layout.addWidget(self.asset_id_entry)
        layout.addLayout(asset_id_layout)

        add_tags_layout = QHBoxLayout()
        add_tags_layout.addWidget(QLabel("Tags to ADD:"))
        self.add_tags_entry = QLineEdit()
        self.add_tags_entry.setPlaceholderText("Comma-separated list, e.g., Tag1, Tag2")
        add_tags_layout.addWidget(self.add_tags_entry)
        layout.addLayout(add_tags_layout)

        remove_tags_layout = QHBoxLayout()
        remove_tags_layout.addWidget(QLabel("Tags to REMOVE:"))
        self.remove_tags_entry = QLineEdit()
        self.remove_tags_entry.setPlaceholderText("Comma-separated list, e.g., OldTag")
        remove_tags_layout.addWidget(self.remove_tags_entry)
        layout.addLayout(remove_tags_layout)

        self.apply_tags_button = QPushButton("Apply Tags")
        self.apply_tags_button.clicked.connect(self.start_update_asset_tags)
        layout.addWidget(self.apply_tags_button, alignment=Qt.AlignRight)

        self.single_tag_log = QTextEdit()
        self.single_tag_log.setReadOnly(True)
        layout.addWidget(self.single_tag_log)


    def create_bulk_tagging_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        self.tabs.addTab(tab, "Bulk Tagging (CSV)")

        layout.addWidget(QLabel("CSV file must contain headers: IP, Add Tags, Remove Tags"))

        csv_layout = QHBoxLayout()
        self.select_csv_button = QPushButton("Select CSV File")
        self.csv_path_label = QLabel("No file selected.")
        csv_layout.addWidget(self.select_csv_button)
        csv_layout.addWidget(self.csv_path_label)
        csv_layout.addStretch()
        layout.addLayout(csv_layout)

        self.process_csv_button = QPushButton("Upload and Process")
        self.process_csv_button.setEnabled(False)
        layout.addWidget(self.process_csv_button)

        self.bulk_tag_log = QTextEdit()
        self.bulk_tag_log.setReadOnly(True)
        layout.addWidget(self.bulk_tag_log)

        self.select_csv_button.clicked.connect(self.select_csv_file)
        self.process_csv_button.clicked.connect(self.start_bulk_tagging)

    def create_settings_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        self.tabs.addTab(tab, "Settings")

        placeholder_label = QLabel("<Will add customizability and other features to this later>")
        placeholder_label.setAlignment(Qt.AlignCenter)
        placeholder_label.setStyleSheet("font-style: italic; color: grey;")
        layout.addWidget(placeholder_label)

    def update_status(self, text, color):
        self.status_label.setText(f"Status: {text}")
        self.status_label.setStyleSheet(f"color: {color};")

    def set_buttons_enabled(self, enabled):
        """Enable/disable all major action buttons."""
    
        buttons = [
            self.fetch_assets_button,
            self.apply_tags_button,
            self.process_csv_button,
            self.select_csv_button
        ]

        self.query_type_combo.setEnabled(enabled)
        self.search_entry.setEnabled(enabled)

   
        if self.process_csv_button:
            csv_file_selected = self.csv_path_label.text() != "No file selected."
            self.process_csv_button.setEnabled(enabled and csv_file_selected)

        for button in buttons:

            if button is not self.process_csv_button:
                button.setEnabled(enabled)

    def check_connection(self):
        # This will always be true since the app can't start without a client
        if not self.api_client:
            self.show_error_signal.emit("Connection Lost", "The API client is not available. Please restart the application.")
            return False
        return True

    def run_in_thread(self, target_func, on_finish, on_error, *args, **kwargs):
        """Generic function to run any task in a background thread."""
        self.thread = QThread()
      
        self.worker = Worker(target_func, *args, **kwargs)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(on_finish)
        self.worker.error.connect(on_error)

        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()

    def handle_api_error(self, error_msg, title="API Error"):
        """Central function to handle all API errors."""
        self.update_status(f"Error: {error_msg}", "red")
        self.set_buttons_enabled(True)
        self.show_error_signal.emit(title, error_msg)  # Use the safe signal/slot


    def start_query_devices(self):
        if not self.check_connection(): return

        criteria = self.search_entry.text().strip() or None
        query_type = self.query_type_combo.currentText()

        search_by = 'ip'  # Default
        if query_type == "Hostname":
            search_by = 'hostname'

        self.set_buttons_enabled(False)
        if criteria:
            self.update_status(f"Querying for {search_by} '{criteria}'...", "orange")
        else:
            self.update_status("Querying for all assets...", "orange")
            search_by = 'all'

        def on_finish(assets):
            self.update_status(f"Found {len(assets)} device(s)." if assets else "No devices found.",
                               "green" if assets else "orange")

            self.populate_table(assets, ['id', 'ip', 'hostname', 'tags'])

            self.set_buttons_enabled(True)

        on_error = lambda e: self.handle_api_error(e, "Asset Query Error")

        self.run_in_thread(
            self.api_client.query_assets,
            on_finish,
            on_error,
            criteria=criteria,
            search_by=search_by
        )

    def start_query_tags(self):
        if not self.check_connection(): return
        name = self.tag_query_entry.text() or None
        self.set_buttons_enabled(False)
        self.update_status("Querying tags...", "orange")

        def on_finish(tags):
            self.update_status(f"Found {len(tags)} tag(s)." if tags else "No tags found.",
                               "green" if tags else "orange")
            self.populate_table(tags, ['id', 'name', 'created', 'modified'])
            self.set_buttons_enabled(True)

        self.run_in_thread(self.api_client.query_tags, on_finish, lambda e: self.handle_api_error(e, "Tag Query Error"),
                           name)



    def populate_table(self, data, headers):
        self.results_table.setRowCount(0)  # Clears table first
        self.results_table.setRowCount(len(data))
        self.results_table.setColumnCount(len(headers))
        self.results_table.setHorizontalHeaderLabels([h.upper() for h in headers])

        for row_index, row_data in enumerate(data):
            for col_index, header in enumerate(headers):
                item_text = str(row_data.get(header, ''))
                self.results_table.setItem(row_index, col_index, QTableWidgetItem(item_text))

        self.results_table.resizeColumnsToContents()
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.results_table.horizontalHeader().setSectionResizeMode(len(headers) - 1,
                                                                   QHeaderView.ResizeToContents)  

   

    def select_csv_file(self):
        filepath, _ = QFileDialog.getOpenFileName(self, "Select a CSV file", "", "CSV Files (*.csv);;All Files (*)")
        if filepath:
            self.csv_path_label.setText(filepath)
            if self.api_client:  # Only enable if we are also connected
                self.process_csv_button.setEnabled(True)

    def start_bulk_tagging(self):
        if not self.check_connection(): return
        filepath = self.csv_path_label.text()
        if filepath == "No file selected.":
            QMessageBox.warning(self, "File Not Found", "Please select a CSV file first.")
            return

        self.set_buttons_enabled(False)
        self.bulk_tag_log.append(f"Submitting bulk tagging job from {filepath}...")

        def on_finish(result):
            self.bulk_tag_log.append(f"SUCCESS: {result}\n")
            self.set_buttons_enabled(True)

        def on_error(error):
            self.bulk_tag_log.append(f"ERROR: {error}\n")
            QMessageBox.critical(self, "Bulk Tagging Error", error)
            self.set_buttons_enabled(True)

        self.run_in_thread(
            self.api_client.bulk_tag_assets_from_csv,
            on_finish, on_error,
            filepath
        )


# Application Entry Point 
if __name__ == "__main__":
    setup_logging()
    app = QApplication(sys.argv)

    login_dialog = LoginDialog()

    if login_dialog.exec() == QDialog.Accepted:
        successful_client = login_dialog.api_client

        # Create the main window instance
        window = QualysDashboardApp(api_client=successful_client)

        # Shows the window first, THEN starts the fetch
        window.show()

        # Trigger the initial asset fetch automatically
        window.start_fetch_assets_cache()

        sys.exit(app.exec())
    else:
        logging.info("Login cancelled by user. Exiting application.")
        sys.exit(0)
