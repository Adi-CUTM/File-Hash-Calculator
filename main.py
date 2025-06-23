import os
import sys
import time
import hashlib
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QLineEdit, QPushButton, QTextEdit, QFileDialog, 
                             QTabWidget, QListWidget, QMessageBox, QProgressBar, QAction, 
                             QMenuBar, QComboBox, QToolBar)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QIntValidator

# Theme styles
STYLES = {
    "light": """
        QWidget {
            background-color: #f0f0f0;
            color: #000000;
        }
        QTextEdit, QListWidget, QLineEdit {
            background-color: #ffffff;
            border: 1px solid #cccccc;
        }
        QPushButton {
            background-color: #e0e0e0;
            border: 1px solid #aaaaaa;
            padding: 5px;
        }
        QPushButton:hover {
            background-color: #d0d0d0;
        }
        QTabWidget::pane {
            border: 1px solid #cccccc;
        }
        QProgressBar {
            border: 1px solid #aaaaaa;
            text-align: center;
        }
        QProgressBar::chunk {
            background-color: #4CAF50;
        }
        QComboBox {
            background-color: #ffffff;
            border: 1px solid #cccccc;
            padding: 3px;
            min-width: 100px;
        }
    """,
    "dark": """
        QWidget {
            background-color: #2d2d2d;
            color: #ffffff;
        }
        QTextEdit, QListWidget, QLineEdit {
            background-color: #3d3d3d;
            color: #ffffff;
            border: 1px solid #555555;
        }
        QPushButton {
            background-color: #444444;
            color: #ffffff;
            border: 1px solid #666666;
            padding: 5px;
        }
        QPushButton:hover {
            background-color: #555555;
        }
        QTabWidget::pane {
            border: 1px solid #555555;
            background: #3d3d3d;
        }
        QProgressBar {
            border: 1px solid #444444;
            text-align: center;
            color: white;
        }
        QProgressBar::chunk {
            background-color: #2e7d32;
        }
        QComboBox {
            background-color: #3d3d3d;
            color: #ffffff;
            border: 1px solid #555555;
            padding: 3px;
            min-width: 100px;
        }
    """,
    "blue": """
        QWidget {
            background-color: #e6f3ff;
            color: #003366;
        }
        QTextEdit, QListWidget, QLineEdit {
            background-color: #ffffff;
            border: 1px solid #99c2ff;
        }
        QPushButton {
            background-color: #4da6ff;
            color: white;
            border: 1px solid #1a8cff;
            padding: 5px;
            border-radius: 4px;
        }
        QPushButton:hover {
            background-color: #1a8cff;
        }
        QTabWidget::pane {
            border: 1px solid #99c2ff;
            background: #ffffff;
        }
        QProgressBar {
            border: 1px solid #99c2ff;
            text-align: center;
        }
        QProgressBar::chunk {
            background-color: #4da6ff;
        }
        QComboBox {
            background-color: #ffffff;
            border: 1px solid #99c2ff;
            padding: 3px;
            min-width: 100px;
        }
    """
}

class HashCalculator(QThread):
    """Worker thread for calculating hashes to prevent GUI freezing"""
    progress_updated = pyqtSignal(int)
    hashes_calculated = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    batch_complete = pyqtSignal(list)

    def __init__(self, file_paths, verify_hash=None, compare_mode=False):
        super().__init__()
        self.file_paths = file_paths if isinstance(file_paths, list) else [file_paths]
        self.verify_hash = verify_hash
        self.compare_mode = compare_mode
        self.results = []

    def run(self):
        try:
            total_files = len(self.file_paths)
            for i, file_path in enumerate(self.file_paths):
                if self.compare_mode and len(self.file_paths) != 2:
                    self.error_occurred.emit("Compare mode requires exactly 2 files")
                    return

                result = self.calculate_file_hashes(file_path)
                if result:
                    self.results.append(result)
                    self.progress_updated.emit(int((i + 1) / total_files * 100))

            if self.compare_mode and len(self.results) == 2:
                comparison = self.compare_hashes(self.results[0], self.results[1])
                self.hashes_calculated.emit(comparison)
            elif self.verify_hash:
                verification = self.verify_hashes(self.results[0], self.verify_hash)
                self.hashes_calculated.emit(verification)
            elif len(self.results) > 1:
                self.batch_complete.emit(self.results)
            else:
                self.hashes_calculated.emit(self.results[0])

        except Exception as e:
            self.error_occurred.emit(str(e))

    def calculate_file_hashes(self, file_path):
        """Calculate multiple hash values for a single file"""
        if not os.path.exists(file_path):
            self.error_occurred.emit(f"File '{file_path}' does not exist")
            return None
        
        if not os.path.isfile(file_path):
            self.error_occurred.emit(f"'{file_path}' is not a file")
            return None

        try:
            # Initialize hash objects for all algorithms
            hashers = {
                'MD5': hashlib.md5(),
                'SHA-1': hashlib.sha1(),
                'SHA-256': hashlib.sha256(),
                'SHA-512': hashlib.sha512(),
                'BLAKE2b': hashlib.blake2b(),
                'BLAKE2s': hashlib.blake2s(),
                'SHA3-256': hashlib.sha3_256(),
                'SHA3-512': hashlib.sha3_512()
            }

            # Get file info
            stat = os.stat(file_path)
            file_info = {
                'name': os.path.basename(file_path),
                'path': os.path.abspath(file_path),
                'size': stat.st_size,
                'modified': time.ctime(stat.st_mtime)
            }

            # Read file and update hashes in chunks
            with open(file_path, 'rb') as f:
                file_size = os.path.getsize(file_path)
                chunk_size = 4096
                bytes_read = 0
                
                while chunk := f.read(chunk_size):
                    for hasher in hashers.values():
                        hasher.update(chunk)
                    bytes_read += len(chunk)
                    progress = int(bytes_read / file_size * 100)
                    self.progress_updated.emit(progress)

            # Prepare results with all hash types
            hashes = {algo: hasher.hexdigest() for algo, hasher in hashers.items()}
            return {'file_info': file_info, 'hashes': hashes}

        except Exception as e:
            self.error_occurred.emit(f"Error processing {file_path}: {str(e)}")
            return None

    def compare_hashes(self, result1, result2):
        """Compare hashes of two files"""
        comparison = {}
        for algo in result1['hashes'].keys():
            comparison[algo] = {
                'file1': result1['hashes'][algo],
                'file2': result2['hashes'][algo],
                'match': result1['hashes'][algo] == result2['hashes'][algo]
            }
        return {
            'type': 'comparison',
            'file1_info': result1['file_info'],
            'file2_info': result2['file_info'],
            'comparison': comparison
        }

    def verify_hashes(self, result, verify_hash):
        """Verify a file against a known hash"""
        verification = {}
        for algo, hash_value in result['hashes'].items():
            verification[algo] = {
                'calculated': hash_value,
                'provided': verify_hash,
                'match': hash_value.lower() == verify_hash.lower()
            }
        return {
            'type': 'verification',
            'file_info': result['file_info'],
            'verification': verification
        }

class BatchHashWorker(QThread):
    progress_updated = pyqtSignal(int, str)
    batch_complete = pyqtSignal(list)
    error_occurred = pyqtSignal(str)

    def __init__(self, file_paths, max_threads=4):
        super().__init__()
        self.file_paths = file_paths
        self.max_threads = max_threads
        self.stop_flag = False

    def run(self):
        try:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            results = []
            completed = 0
            total = len(self.file_paths)

            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future_to_file = {
                    executor.submit(self.process_single_file, fp): fp 
                    for fp in self.file_paths
                }

                for future in as_completed(future_to_file):
                    if self.stop_flag:
                        break

                    file_path = future_to_file[future]
                    try:
                        result = future.result()
                        if result:
                            results.append(result)
                            completed += 1
                            progress = int(completed / total * 100)
                            self.progress_updated.emit(progress, file_path)
                    except Exception as e:
                        self.error_occurred.emit(f"{file_path}: {str(e)}")

            if not self.stop_flag:
                self.batch_complete.emit(results)

        except Exception as e:
            self.error_occurred.emit(f"Batch error: {str(e)}")

    def process_single_file(self, file_path):
        try:
            # Initialize all hash algorithms
            hashers = {
                'MD5': hashlib.md5(),
                'SHA-1': hashlib.sha1(),
                'SHA-256': hashlib.sha256(),
                'SHA-512': hashlib.sha512(),
                'BLAKE2b': hashlib.blake2b(),
                'BLAKE2s': hashlib.blake2s(),
                'SHA3-256': hashlib.sha3_256(),
                'SHA3-512': hashlib.sha3_512()
            }

            # Get file info
            stat = os.stat(file_path)
            file_info = {
                'name': os.path.basename(file_path),
                'path': os.path.abspath(file_path),
                'size': stat.st_size,
                'modified': time.ctime(stat.st_mtime)
            }

            # Calculate hashes
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    for hasher in hashers.values():
                        hasher.update(chunk)

            hashes = {algo: hasher.hexdigest() for algo, hasher in hashers.items()}
            return {'file_info': file_info, 'hashes': hashes}

        except Exception as e:
            raise Exception(f"Couldn't process {file_path}: {str(e)}")

    def stop(self):
        self.stop_flag = True

class HashCalculatorApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced File Hash Calculator")
        self.setGeometry(100, 100, 800, 600)
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)
        
        self.hash_thread = None
        self.batch_worker = None
        
        self.create_menu_bar()
        self.create_tabs()
        self.create_status_bar()
        
        # Set default theme
        self.set_theme('light')

    def create_menu_bar(self):
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('&File')
        exit_action = QAction('Exit', self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Create toolbar for theme selector
        toolbar = self.addToolBar('Theme')
        toolbar.setMovable(False)
        
        # Theme label
        theme_label = QLabel("Theme:")
        toolbar.addWidget(theme_label)
        
        # Theme combo box
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Light", "Dark", "Blue"])
        self.theme_combo.currentTextChanged.connect(self.set_theme)
        toolbar.addWidget(self.theme_combo)

    def set_theme(self, theme_name):
        theme_name = theme_name.lower()
        if theme_name in STYLES:
            self.setStyleSheet(STYLES[theme_name])
            self.status_bar.showMessage(f"Switched to {theme_name} theme", 2000)
        else:
            QMessageBox.warning(self, "Error", f"Theme '{theme_name}' not found")
    
    def create_tabs(self):
        self.tabs = QTabWidget()
        self.layout.addWidget(self.tabs)
        
        # Single File Tab
        self.single_file_tab = QWidget()
        self.setup_single_file_tab()
        self.tabs.addTab(self.single_file_tab, "Single File")
        
        # Batch Processing Tab
        self.batch_tab = QWidget()
        self.setup_batch_tab()
        self.tabs.addTab(self.batch_tab, "Batch Processing")
        
        # File Comparison Tab
        self.compare_tab = QWidget()
        self.setup_compare_tab()
        self.tabs.addTab(self.compare_tab, "File Comparison")
        
        # Hash Verification Tab
        self.verify_tab = QWidget()
        self.setup_verify_tab()
        self.tabs.addTab(self.verify_tab, "Hash Verification")
    
    def setup_single_file_tab(self):
        layout = QVBoxLayout()
        
        # File selection
        file_layout = QHBoxLayout()
        self.file_path = QLineEdit()
        self.file_path.setPlaceholderText("Select a file...")
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(lambda: self.select_file(self.file_path))
        file_layout.addWidget(self.file_path)
        file_layout.addWidget(browse_btn)
        
        # Calculate button
        calculate_btn = QPushButton("Calculate Hashes")
        calculate_btn.clicked.connect(self.calculate_single_file)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        # Results display
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        
        layout.addLayout(file_layout)
        layout.addWidget(calculate_btn)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.results_text)
        self.single_file_tab.setLayout(layout)
    
    def setup_batch_tab(self):
        layout = QVBoxLayout()
        
        # File list
        self.file_list = QListWidget()
        add_files_btn = QPushButton("Add Files")
        add_files_btn.clicked.connect(self.add_batch_files)
        clear_list_btn = QPushButton("Clear List")
        clear_list_btn.clicked.connect(self.file_list.clear)
        
        # Parallel processing controls
        parallel_layout = QHBoxLayout()
        parallel_layout.addWidget(QLabel("Threads:"))
        self.thread_count = QLineEdit("4")
        self.thread_count.setValidator(QIntValidator(1, 16))
        parallel_layout.addWidget(self.thread_count)
        
        # Action buttons
        action_layout = QHBoxLayout()
        process_btn = QPushButton("Process Batch")
        process_btn.clicked.connect(self.process_batch)
        clear_results_btn = QPushButton("Clear Results")
        clear_results_btn.clicked.connect(self.clear_batch_results)
        stop_btn = QPushButton("Stop")
        stop_btn.clicked.connect(self.stop_batch_processing)
        action_layout.addWidget(process_btn)
        action_layout.addWidget(clear_results_btn)
        action_layout.addWidget(stop_btn)
        
        # Progress bar
        self.batch_progress = QProgressBar()
        self.batch_progress.setVisible(False)
        
        # Results display
        self.batch_results = QTextEdit()
        self.batch_results.setReadOnly(True)
        
        # Add widgets to layout
        layout.addWidget(QLabel("Files to process:"))
        layout.addWidget(self.file_list)
        
        btn_layout = QHBoxLayout()
        btn_layout.addWidget(add_files_btn)
        btn_layout.addWidget(clear_list_btn)
        layout.addLayout(btn_layout)
        
        layout.addLayout(parallel_layout)
        layout.addLayout(action_layout)
        layout.addWidget(self.batch_progress)
        layout.addWidget(self.batch_results)
        
        self.batch_tab.setLayout(layout)

    def clear_batch_results(self):
        self.batch_results.clear()
    
    def setup_compare_tab(self):
        layout = QVBoxLayout()
        
        # File 1 selection
        file1_layout = QHBoxLayout()
        self.compare_file1 = QLineEdit()
        self.compare_file1.setPlaceholderText("Select first file...")
        browse1_btn = QPushButton("Browse")
        browse1_btn.clicked.connect(lambda: self.select_file(self.compare_file1))
        file1_layout.addWidget(self.compare_file1)
        file1_layout.addWidget(browse1_btn)
        
        # File 2 selection
        file2_layout = QHBoxLayout()
        self.compare_file2 = QLineEdit()
        self.compare_file2.setPlaceholderText("Select second file...")
        browse2_btn = QPushButton("Browse")
        browse2_btn.clicked.connect(lambda: self.select_file(self.compare_file2))
        file2_layout.addWidget(self.compare_file2)
        file2_layout.addWidget(browse2_btn)
        
        # Compare button
        compare_btn = QPushButton("Compare Files")
        compare_btn.clicked.connect(self.compare_files)
        
        # Progress bar
        self.compare_progress = QProgressBar()
        self.compare_progress.setVisible(False)
        
        # Results display
        self.compare_results = QTextEdit()
        self.compare_results.setReadOnly(True)
        
        layout.addLayout(file1_layout)
        layout.addLayout(file2_layout)
        layout.addWidget(compare_btn)
        layout.addWidget(self.compare_progress)
        layout.addWidget(self.compare_results)
        self.compare_tab.setLayout(layout)
    
    def setup_verify_tab(self):
        layout = QVBoxLayout()
        
        # File selection
        file_layout = QHBoxLayout()
        self.verify_file = QLineEdit()
        self.verify_file.setPlaceholderText("Select file to verify...")
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(lambda: self.select_file(self.verify_file))
        file_layout.addWidget(self.verify_file)
        file_layout.addWidget(browse_btn)
        
        # Hash input
        hash_layout = QHBoxLayout()
        self.hash_input = QLineEdit()
        self.hash_input.setPlaceholderText("Enter known hash to verify against...")
        hash_layout.addWidget(self.hash_input)
        
        # Algorithm selection
        self.hash_algo = QLineEdit()
        self.hash_algo.setPlaceholderText("Algorithm (optional, will try all if empty)")
        hash_layout.addWidget(self.hash_algo)
        
        # Verify button
        verify_btn = QPushButton("Verify Hash")
        verify_btn.clicked.connect(self.verify_hash)
        
        # Progress bar
        self.verify_progress = QProgressBar()
        self.verify_progress.setVisible(False)
        
        # Results display
        self.verify_results = QTextEdit()
        self.verify_results.setReadOnly(True)
        
        layout.addLayout(file_layout)
        layout.addWidget(QLabel("Known hash:"))
        layout.addLayout(hash_layout)
        layout.addWidget(verify_btn)
        layout.addWidget(self.verify_progress)
        layout.addWidget(self.verify_results)
        self.verify_tab.setLayout(layout)
    
    def create_status_bar(self):
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready")
    
    def select_file(self, line_edit):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            line_edit.setText(file_path)
    
    def add_batch_files(self):
        file_paths, _ = QFileDialog.getOpenFileNames(self, "Select Files")
        if file_paths:
            self.file_list.addItems(file_paths)
    
    def calculate_single_file(self):
        file_path = self.file_path.text()
        if not file_path:
            QMessageBox.warning(self, "Error", "Please select a file first")
            return
        
        self.start_calculation(file_path, self.results_text, self.progress_bar)
    
    def process_batch(self):
        if self.file_list.count() == 0:
            QMessageBox.warning(self, "Error", "Please add files to process first")
            return
        
        try:
            threads = int(self.thread_count.text())
            if not 1 <= threads <= 16:
                raise ValueError
        except ValueError:
            QMessageBox.warning(self, "Error", "Please enter thread count (1-16)")
            return
        
        file_paths = [self.file_list.item(i).text() for i in range(self.file_list.count())]
        self.start_batch_process(file_paths, threads)
    
    def start_batch_process(self, file_paths, threads=4):
        if hasattr(self, 'batch_worker') and self.batch_worker is not None and self.batch_worker.isRunning():
            QMessageBox.warning(self, "Busy", "Batch processing already running")
            return
        
        self.batch_results.clear()
        self.batch_progress.setVisible(True)
        self.batch_progress.setValue(0)
        
        self.batch_worker = BatchHashWorker(file_paths, threads)
        self.batch_worker.batch_complete.connect(self.display_batch_results)
        self.batch_worker.error_occurred.connect(
            lambda error: self.show_error(error, self.batch_progress))
        self.batch_worker.progress_updated.connect(
            lambda p, f: self.update_batch_progress(p, f))
        self.batch_worker.start()

    def stop_batch_processing(self):
        if hasattr(self, 'batch_worker') and self.batch_worker is not None:
            if self.batch_worker.isRunning():
                self.batch_worker.stop()
                self.status_bar.showMessage("Batch processing stopped", 3000)
            self.batch_worker = None
    
    def compare_files(self):
        file1 = self.compare_file1.text()
        file2 = self.compare_file2.text()
        
        if not file1 or not file2:
            QMessageBox.warning(self, "Error", "Please select both files to compare")
            return
        
        self.start_comparison([file1, file2])
    
    def verify_hash(self):
        file_path = self.verify_file.text()
        known_hash = self.hash_input.text().strip()
        
        if not file_path or not known_hash:
            QMessageBox.warning(self, "Error", "Please select a file and enter a hash to verify")
            return
        
        # Auto-detect hash algorithm based on length
        hash_length = len(known_hash)
        algo_hint = ""
        
        if hash_length == 32:
            algo_hint = "MD5"
        elif hash_length == 40:
            algo_hint = "SHA-1"
        elif hash_length == 64:
            algo_hint = "SHA-256 or BLAKE2s"
        elif hash_length == 128:
            algo_hint = "SHA-512 or BLAKE2b"
        
        if algo_hint:
            reply = QMessageBox.question(
                self, 'Algorithm Hint', 
                f"Detected possible algorithm: {algo_hint}\nUse this for verification?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
            
            if reply == QMessageBox.Yes:
                self.hash_algo.setText(algo_hint.split()[0])  # Take first suggestion
        
        algo = self.hash_algo.text().strip() or None
        self.start_verification(file_path, known_hash, algo)
    
    def start_calculation(self, file_path, output_widget, progress_bar):
        if self.hash_thread and self.hash_thread.isRunning():
            QMessageBox.warning(self, "Busy", "A calculation is already in progress")
            return
        
        output_widget.clear()
        progress_bar.setVisible(True)
        progress_bar.setValue(0)
        
        self.hash_thread = HashCalculator(file_path)
        self.hash_thread.hashes_calculated.connect(
            lambda result: self.display_results(result, output_widget, progress_bar))
        self.hash_thread.error_occurred.connect(
            lambda error: self.show_error(error, progress_bar))
        self.hash_thread.progress_updated.connect(progress_bar.setValue)
        self.hash_thread.start()
    
    def start_comparison(self, file_paths):
        if self.hash_thread and self.hash_thread.isRunning():
            QMessageBox.warning(self, "Busy", "A calculation is already in progress")
            return
        
        self.compare_results.clear()
        self.compare_progress.setVisible(True)
        self.compare_progress.setValue(0)
        
        self.hash_thread = HashCalculator(file_paths, compare_mode=True)
        self.hash_thread.hashes_calculated.connect(
            lambda result: self.display_comparison_results(result))
        self.hash_thread.error_occurred.connect(
            lambda error: self.show_error(error, self.compare_progress))
        self.hash_thread.progress_updated.connect(self.compare_progress.setValue)
        self.hash_thread.start()
    
    def start_verification(self, file_path, known_hash, algo=None):
        if self.hash_thread and self.hash_thread.isRunning():
            QMessageBox.warning(self, "Busy", "A calculation is already in progress")
            return
        
        self.verify_results.clear()
        self.verify_progress.setVisible(True)
        self.verify_progress.setValue(0)
        
        self.hash_thread = HashCalculator(file_path, verify_hash=known_hash)
        self.hash_thread.hashes_calculated.connect(
            lambda result: self.display_verification_results(result, algo))
        self.hash_thread.error_occurred.connect(
            lambda error: self.show_error(error, self.verify_progress))
        self.hash_thread.progress_updated.connect(self.verify_progress.setValue)
        self.hash_thread.start()
    
    def update_batch_progress(self, progress, current_file):
        self.batch_progress.setValue(progress)
        self.status_bar.showMessage(
            f"Processing: {os.path.basename(current_file)}", 1000)
    
    def display_results(self, result, output_widget, progress_bar):
        progress_bar.setVisible(False)
        
        file_info = result['file_info']
        hashes = result['hashes']
        
        output = "FILE INFORMATION:\n"
        output += f"Name: {file_info['name']}\n"
        output += f"Path: {file_info['path']}\n"
        output += f"Size: {file_info['size']} bytes\n"
        output += f"Last Modified: {file_info['modified']}\n\n"
        output += "HASH VALUES:\n"
        
        for algo, value in hashes.items():
            output += f"{algo + ':':<10} {value}\n"
        
        output_widget.setPlainText(output)
        self.status_bar.showMessage("Calculation complete", 3000)
    
    def display_batch_results(self, results):
        self.batch_progress.setVisible(False)
        
        output = "BATCH PROCESSING RESULTS:\n\n"
        for result in results:
            file_info = result['file_info']
            hashes = result['hashes']
            
            output += f"FILE: {file_info['name']}\n"
            output += f"PATH: {file_info['path']}\n"
            output += f"SIZE: {file_info['size']} bytes\n"
            output += f"MODIFIED: {file_info['modified']}\n"
            output += "HASHES:\n"
            
            # Display all hash types with consistent formatting
            output += f"  MD5:       {hashes['MD5']}\n"
            output += f"  SHA-1:     {hashes['SHA-1']}\n"
            output += f"  SHA-256:   {hashes['SHA-256']}\n"
            output += f"  SHA-512:   {hashes['SHA-512']}\n"
            output += f"  BLAKE2b:   {hashes['BLAKE2b']}\n"
            output += f"  BLAKE2s:   {hashes['BLAKE2s']}\n"
            output += f"  SHA3-256:  {hashes['SHA3-256']}\n"
            output += f"  SHA3-512:  {hashes['SHA3-512']}\n"
            
            output += "-" * 50 + "\n"
        
        self.batch_results.setPlainText(output)
        self.status_bar.showMessage(f"Processed {len(results)} files", 3000)
    
    def display_comparison_results(self, result):
        self.compare_progress.setVisible(False)
        
        file1_info = result['file1_info']
        file2_info = result['file2_info']
        comparison = result['comparison']
        
        output = "FILE COMPARISON RESULTS:\n\n"
        output += "FILE 1:\n"
        output += f"  Name: {file1_info['name']}\n"
        output += f"  Path: {file1_info['path']}\n"
        output += f"  Size: {file1_info['size']} bytes\n"
        output += f"  Modified: {file1_info['modified']}\n\n"
        output += "FILE 2:\n"
        output += f"  Name: {file2_info['name']}\n"
        output += f"  Path: {file2_info['path']}\n"
        output += f"  Size: {file2_info['size']} bytes\n"
        output += f"  Modified: {file2_info['modified']}\n\n"
        output += "COMPARISON:\n"
        
        all_match = True
        for algo, data in comparison.items():
            match = data['match']
            if not match:
                all_match = False
            status = "MATCH" if match else "DIFFERENT"
            output += f"{algo + ':':<10} {status}\n"
            if not match:
                output += f"  File 1: {data['file1']}\n"
                output += f"  File 2: {data['file2']}\n"
        
        output += "\nOVERALL: " + ("FILES ARE IDENTICAL" if all_match else "FILES ARE DIFFERENT")
        
        self.compare_results.setPlainText(output)
        self.status_bar.showMessage("Comparison complete", 3000)
    
    def display_verification_results(self, result, algo=None):
        self.verify_progress.setVisible(False)
        
        file_info = result['file_info']
        verification = result['verification']
        
        output = "HASH VERIFICATION RESULTS:\n\n"
        output += "FILE INFORMATION:\n"
        output += f"Name: {file_info['name']}\n"
        output += f"Path: {file_info['path']}\n"
        output += f"Size: {file_info['size']} bytes\n"
        output += f"Modified: {file_info['modified']}\n\n"
        
        if algo:
            # Verify against specific algorithm
            if algo.upper() in verification:
                data = verification[algo.upper()]
                output += f"ALGORITHM: {algo.upper()}\n"
                output += f"PROVIDED HASH:  {data['provided']}\n"
                output += f"CALCULATED HASH: {data['calculated']}\n"
                output += "\nRESULT: " + ("VERIFIED" if data['match'] else "NOT VERIFIED")
            else:
                output += f"Error: Algorithm '{algo}' not supported"
        else:
            # Check all algorithms
            output += "CHECKING ALL ALGORITHMS:\n\n"
            verified = False
            for algo, data in verification.items():
                if data['match']:
                    output += f"VERIFIED with {algo}:\n"
                    output += f"  Provided:  {data['provided']}\n"
                    output += f"  Calculated: {data['calculated']}\n\n"
                    verified = True
                    break
            
            if not verified:
                output += "No matching hash found for any algorithm\n"
                output += "Calculated hashes:\n"
                for algo, data in verification.items():
                    output += f"  {algo + ':':<10} {data['calculated']}\n"
        
        self.verify_results.setPlainText(output)
        self.status_bar.showMessage("Verification complete", 3000)
    
    def show_error(self, error, progress_bar):
        progress_bar.setVisible(False)
        QMessageBox.critical(self, "Error", error)
        self.status_bar.showMessage("Error occurred", 3000)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Set Fusion style as base for all themes
    app.setStyle('Fusion')
    
    window = HashCalculatorApp()
    window.show()
    sys.exit(app.exec_())