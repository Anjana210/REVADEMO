document.addEventListener('DOMContentLoaded', () => {

    // --- CACHE DOM ELEMENTS ---
    // STEP 1 ELEMENTS
    const refUploadForm = document.getElementById('ref-upload-form');
    const refUploadBtn = document.getElementById('ref-process-btn');
    const refUploadStatus = document.getElementById('ref-upload-status');
    const refFileInput = document.getElementById('ref-file-input');
    const refDropZone = document.getElementById('ref-drop-zone');
    const refFileNameSpan = document.getElementById('ref-file-name');
    let selectedRefFile = null;

    // STEP 2 ELEMENTS
    const applyRefChangesBtn = document.getElementById('apply-ref-changes-btn');
    const refUpdateStatus = document.getElementById('ref-update-status');
    const refDataTableContainer = document.getElementById('reference-data-table-container');

    // STEP 3 & 4 ELEMENTS (Original form)
    const billingForm = document.getElementById('billing-form');
    const processBtn = document.getElementById('process-btn');
    const processBtnIcon = processBtn.querySelector('i');
    const processBtnText = processBtn.querySelector('span');
    const uploadStatus = document.getElementById('upload-status');
    const fileInput = document.getElementById('file-input');
    const dropZone = document.getElementById('drop-zone');
    const fileNameSpan = document.getElementById('file-name');
    let selectedFile = null;
    
    // STEP 4 ELEMENTS
    const billMonthInput = document.getElementById('billing-month');
    const tariffInput = document.getElementById('tariff');
    const addChargeBtn = document.getElementById('add-charge-btn');
    const chargesContainer = document.getElementById('other-charges-container');

    // STEP 5 ELEMENTS
    const fetchBtn = document.getElementById('fetch-data-btn');
    const fetchBtnIcon = fetchBtn.querySelector('i');
    const fetchBtnText = fetchBtn.querySelector('span');
    const searchMonthInput = document.getElementById('search-month');
    const fetchStatus = document.getElementById('fetch-status');
    const downloadAllBtn = document.getElementById('download-all-btn');
    const clearDataBtn = document.getElementById('clear-data-btn');
    
    // NEW: Cache Icon and Text Span for Download All Button
    const downloadAllBtnIcon = downloadAllBtn ? downloadAllBtn.querySelector('i') : null;
    const downloadAllBtnText = downloadAllBtn ? downloadAllBtn.querySelector('span') : null;
    
    const resultsTbody = document.getElementById('results-tbody');
    const billTable = document.getElementById('bill-results-table');
    const colToggleBtn = document.getElementById('col-toggle-btn');
    const colToggleMenu = document.getElementById('col-toggle-menu');

    // STEP CONTAINERS
    const step1Container = document.getElementById('step-1-container');
    const step2Container = document.getElementById('step-2-container');
    
    // NEW TAB ELEMENTS
    const tabMasterBtn = document.getElementById('tab-master-data');
    const tabBillingBtn = document.getElementById('tab-billing-data');
    const tabMasterContent = document.getElementById('tab-content-master');
    const tabBillingContent = document.getElementById('tab-content-billing');
    // END NEW TAB ELEMENTS


    // MODAL ELEMENTS
    const modal = document.getElementById('bill-details-modal');
    const modalBackdrop = document.getElementById('modal-backdrop');
    const modalCloseBtn = document.getElementById('modal-close-btn');
    const modalDetailsContainer = document.getElementById('modal-bill-details');

    const COLUMN_SETTINGS_KEY = 'revaLiteBillColumnSettings';


    // --- Global state ---
    let currentBillData = [];
    let currentRefData = []; // New array to hold reference table data
    let chargeCount = 0; 
    let step1Complete = false; // Flag to enable visibility of subsequent steps


    // --- HELPER: Show Status Message ---
    function showStatus(element, message, type = 'danger') {
        let icon = type === 'success' ? 'fa-check-circle' : 'fa-exclamation-triangle';
        let classes = type === 'success' ? 
            'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300' :
            'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300';
        
            // NEW CODE (Removes the icon/tick mark)
            element.innerHTML = `
                <div class="${classes} p-4 rounded-lg text-sm font-medium flex items-center gap-3" role="alert">
                    <span>${message}</span>
                </div>
            `;
    }

    // --- HELPER: Toggle Button Spinner ---
    function toggleSpinner(btn, icon, textSpan, newIconClass, newText, isLoading) {
        if (isLoading) {
            btn.disabled = true;
            if (icon) icon.className = `fas ${newIconClass} animate-spin`;
            if (textSpan) textSpan.textContent = newText;
        } else {
            btn.disabled = false;
            if (icon) icon.className = `fas ${newIconClass}`;
            if (textSpan) textSpan.textContent = newText;
        }
    }
    
    // --- HELPER: Format Date for Table/Modal ---
    function formatDate(dateString) {
        if (!dateString) return 'N/A';
        try {
            const date = new Date(dateString);
            if (isNaN(date.getTime())) return dateString; 
            
            if (dateString.includes('T') && (date.getHours() !== 0 || date.getMinutes() !== 0)) {
                 const day = String(date.getDate()).padStart(2, '0');
                 const month = String(date.getMonth() + 1).padStart(2, '0');
                 const year = date.getFullYear();
                 const hours = String(date.getHours()).padStart(2, '0');
                 const minutes = String(date.getMinutes()).padStart(2, '0');
                 return `${day}/${month}/${year} ${hours}:${minutes}`;
            } else {
                const day = String(date.getDate()).padStart(2, '0');
                const month = String(date.getMonth() + 1).padStart(2, '0');
                const year = date.getFullYear();
                return `${day}/${month}/${year}`;
            }
        } catch (e) {
            return dateString;
        }
    }

    // --- NEW: Tab Switching Logic ---
    const activeTabClasses = [
        'bg-blue-100',          // Match sidebar active background
        'text-blue-700',        // Match sidebar active text
        'dark:bg-gray-700',     // Match sidebar dark background
        'dark:text-white',      // Match sidebar dark text
        'rounded-lg',
        'border-b-0'
    ];
    const inactiveTabClasses = [
        'text-slate-500', 
        'dark:text-slate-400',
        'border-b-2',           // FIX: Keep bottom border
        'border-transparent'    // FIX: Make it transparent
    ];
    // All possible active classes from previous versions
    const allPossibleActiveTabClasses = [
        // Current desired
        'bg-blue-100', 'text-blue-700', 'dark:bg-gray-700', 'dark:text-white', 'rounded-lg', 'border-b-0',
        // Previous blue variants to remove
        'bg-blue-50', 'dark:bg-blue-900/40', 'dark:text-blue-300', 'dark:bg-blue-900/60', 'dark:text-blue-400',
        // Old red variants to remove
        'bg-red-100', 'text-red-700', 'dark:bg-red-900/60', 'dark:text-red-400', 'border-red-600', 'text-red-600', 'dark:text-red-500',
        // Inactive style parts to remove
        'border-transparent', 'text-slate-500', 'dark:text-slate-400', 'border-b-2'
    ];

    function switchTab(targetTab) {
        // Reset all buttons
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.remove(...allPossibleActiveTabClasses);
            btn.classList.add(...inactiveTabClasses);
        });

        // Hide all content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.add('hidden');
        });

        // Activate the target tab
        if (targetTab === 'master') {
            tabMasterBtn.classList.remove(...inactiveTabClasses);
            tabMasterBtn.classList.add(...activeTabClasses);
            tabMasterContent.classList.remove('hidden');
        } else if (targetTab === 'billing' && step1Complete) {
            tabBillingBtn.classList.remove(...inactiveTabClasses);
            tabBillingBtn.classList.add(...activeTabClasses);
            tabBillingContent.classList.remove('hidden');
        } else {
            // Fallback: If billing is clicked but not ready, default to master
            tabMasterBtn.classList.remove(...inactiveTabClasses);
            tabMasterBtn.classList.add(...activeTabClasses);
            tabMasterContent.classList.remove('hidden');
        }
    }
    // --- END NEW Tab Switching Logic ---


    // --- Step Visibility Management ---
    function updateStepVisibility() {
        if (step1Complete) {
            // Show Step 2 container
            step2Container.style.display = 'block';
            
            // Enable and style the Billing tab
            tabBillingBtn.disabled = false;
            tabBillingBtn.classList.remove('opacity-50', 'cursor-not-allowed');
            // Hover styles are now handled by the inactiveTabClasses
            
        } else {
            // Hide Step 2 container
            step2Container.style.display = 'none';
            
            // Disable and grey out the Billing tab
            tabBillingBtn.disabled = true;
            tabBillingBtn.classList.add('opacity-50', 'cursor-not-allowed');
            
            // If the user is on the billing tab, switch them back to master
            if (tabBillingContent && tabBillingContent.classList.contains('hidden') === false) {
                switchTab('master');
            }
        }
    }

    // --- Set Default Month ---
    const today = new Date();
    const year = today.getFullYear();
    const month = (today.getMonth() + 1).toString().padStart(2, '0');
    if (billMonthInput) billMonthInput.value = `${year}-${month}`;

    // --- File Input & Drag/Drop Logic (General for both uploads) ---
    function setupFileInput(inputEl, dropEl, nameEl, type) {
        
        inputEl.addEventListener('change', (e) => handleFileSelect(e.target.files, type));
        
        dropEl.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropEl.classList.add('border-red-500', 'bg-slate-50', 'dark:bg-gray-700');
        });
        dropEl.addEventListener('dragleave', (e) => {
            e.preventDefault();
            dropEl.classList.remove('border-red-500', 'bg-slate-50', 'dark:bg-gray-700');
        });
        dropEl.addEventListener('drop', (e) => {
            e.preventDefault();
            dropEl.classList.remove('border-red-500', 'bg-slate-50', 'dark:bg-gray-700');
            handleFileSelect(e.dataTransfer.files, type);
        });

        function handleFileSelect(files, type) {
            if (files.length > 0) {
                // Determine which set of global variables to use based on 'type'
                const fileRef = (type === 'ref') ? 'selectedRefFile' : 'selectedFile';
                const nameSpanRef = (type === 'ref') ? refFileNameSpan : fileNameSpan;

                window[fileRef] = files[0];
                
                if (window[fileRef].type === 'text/csv' || window[fileRef].name.endsWith('.csv')) {
                    nameSpanRef.textContent = window[fileRef].name;
                    nameSpanRef.className = 'text-xs text-green-600 font-semibold';
                } else {
                    nameSpanRef.textContent = 'Invalid file type. Please select a .csv';
                    nameSpanRef.className = 'text-xs text-red-600 font-semibold';
                    window[fileRef] = null;
                }
            }
        }

        return () => {
            const fileRef = (type === 'ref') ? 'selectedRefFile' : 'selectedFile';
            const nameSpanRef = (type === 'ref') ? refFileNameSpan : fileNameSpan;

            nameSpanRef.textContent = (type === 'ref') ? '2-Column CSV file (Device Serial ID, Customer Name)' : '10-Column CSV file (Consumption data)';
            nameSpanRef.className = 'text-xs text-slate-500';
            window[fileRef] = null;
            inputEl.value = ''; 
        };
    }

    const resetRefFileInput = setupFileInput(refFileInput, refDropZone, refFileNameSpan, 'ref');
    const resetBillingFileInput = setupFileInput(fileInput, dropZone, fileNameSpan, 'bill');


    // --- 1. REFERENCE DATA UPLOAD (STEP 1) ---
    refUploadForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        // Check if refUploadBtn is available before proceeding
        if (!refUploadBtn) return; 

        toggleSpinner(refUploadBtn, refUploadBtn.querySelector('i'), refUploadBtn.querySelector('span'), 'fa-spinner', 'Uploading...', true);
        refUploadStatus.innerHTML = '';

        if (!selectedRefFile) {
            if (!refFileInput.files[0]) {
                showStatus(refUploadStatus, 'Please select a CSV file.');
                toggleSpinner(refUploadBtn, refUploadBtn.querySelector('i'), refUploadBtn.querySelector('span'), 'fa-upload', 'Upload & Lock Meters', false);
                return;
            }
            selectedRefFile = refFileInput.files[0];
        }
        
        const formData = new FormData(refUploadForm); 

        try {
            const response = await fetch('/api/upload-reference-data', {
                method: 'POST',
                body: formData,
            });
            const result = await response.json();
            
            if (!response.ok) {
                if (result.code === 'LICENSE_LIMIT_EXCEEDED') {
                    showStatus(refUploadStatus, result.message, 'danger');
                } else {
                    throw new Error(result.message);
                }
            } else {
                showStatus(refUploadStatus, result.message, 'success');
                refUploadForm.reset(); 
                resetRefFileInput();
                step1Complete = true; // Set flag on successful upload
                updateStepVisibility();
                await loadReferenceData(); // Load data for Step 2
                switchTab('billing'); // Automatically switch to the next step/tab
            }

        } catch (error) {
            showStatus(refUploadStatus, `Upload Failed: ${error.message}`, 'danger');
        } finally {
            toggleSpinner(refUploadBtn, refUploadBtn.querySelector('i'), refUploadBtn.querySelector('span'), 'fa-upload', 'Upload & Lock Meters', false);
        }
    });

    // --- 2A. LOAD REFERENCE DATA (STEP 2) ---
    async function loadReferenceData() {
        refDataTableContainer.innerHTML = '<p class="text-sm text-slate-500 dark:text-slate-400">Loading reference data...</p>';
        try {
            const response = await fetch('/api/get-reference-data');
            const result = await response.json();
            if (!response.ok) throw new Error(result.message);

            currentRefData = result.data || [];
            
            if (currentRefData.length === 0) {
                refDataTableContainer.innerHTML = '<p class="text-sm text-red-500 dark:text-red-400">No reference data found. Please complete Step 1.</p>';
                step1Complete = false;
                updateStepVisibility();
                return;
            }

            step1Complete = true;
            updateStepVisibility();
            populateReferenceTable(currentRefData);

        } catch (error) {
            refDataTableContainer.innerHTML = `<p class="text-sm text-red-500 dark:text-red-400">Error loading reference data: ${error.message}</p>`;
        }
    }

    // 2B. POPULATE REFERENCE TABLE (STEP 2)
    function populateReferenceTable(data) {
        let tableHtml = `
            <div class="overflow-x-auto max-h-96 overflow-y-auto rounded-lg shadow ring-1 ring-black ring-opacity-5">
                <table class="min-w-full divide-y divide-slate-300 dark:divide-gray-700">
                    <thead class="bg-slate-50 dark:bg-gray-700 sticky top-0">
                        <tr>
                            <th class="py-3.5 pl-6 pr-3 text-left text-sm font-semibold text-slate-900 dark:text-white">Device Serial ID</th>
                            <th class="px-3 py-3.5 text-left text-sm font-semibold text-slate-900 dark:text-white">Customer Name</th>
                            <th class="relative py-3.5 pl-3 pr-4 text-right"></th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-200 dark:divide-gray-600 bg-white dark:bg-gray-800" id="ref-table-body">
        `;

        data.forEach((item, index) => {
            tableHtml += `
                <tr data-id="${item.id}" data-original-serial="${item.device_serialno}" data-original-name="${item.customer_name}">
                    <td class="py-4 pl-6 pr-3 text-sm font-medium text-slate-900 dark:text-white">
                        <input type="text" class="ref-input ref-serial-input w-full rounded-lg border-slate-300 dark:border-gray-600 bg-white dark:bg-gray-800 shadow-sm text-sm p-1.5" value="${item.device_serialno}">
                        <div class="ref-error ref-serial-error-${index} text-xs text-red-500 mt-1 hidden"></div>
                    </td>
                    <td class="px-3 py-4 text-sm text-slate-500 dark:text-slate-300">
                        <input type="text" class="ref-input ref-name-input w-full rounded-lg border-slate-300 dark:border-gray-600 bg-white dark:bg-gray-800 shadow-sm text-sm p-1.5" value="${item.customer_name}">
                    </td>
                    <td class="relative whitespace-nowrap py-4 pl-3 pr-4 text-right text-sm font-medium">
                        <button type="button" class="update-ref-row-btn text-blue-600 hover:text-blue-900" data-index="${index}" title="Update Row">
                            <i class="fas fa-save"></i>
                        </button>
                    </td>
                </tr>
            `;
        });

        tableHtml += `
                    </tbody>
                </table>
            </div>
        `;
        refDataTableContainer.innerHTML = tableHtml;
    }

    // 2C. APPLY ALL REFERENCE CHANGES (STEP 2)
    if (applyRefChangesBtn) {
        applyRefChangesBtn.addEventListener('click', async () => {
            const changes = [];
            const rows = refDataTableContainer.querySelectorAll('#ref-table-body tr');

            rows.forEach(row => {
                const originalSerial = row.dataset.originalSerial;
                const originalName = row.dataset.originalName;
                const newSerialInput = row.querySelector('.ref-serial-input');
                const newNameInput = row.querySelector('.ref-name-input');

                const newSerial = newSerialInput.value.trim();
                const newCustomerName = newNameInput.value.trim();

                // Only track changed rows (or if fields are empty)
                if (newSerial !== originalSerial || newCustomerName !== originalName || newSerial === '' || newCustomerName === '') {
                    changes.push({
                        originalSerial: originalSerial,
                        newSerial: newSerial,
                        newCustomerName: newCustomerName,
                        element: row
                    });
                }
            });

            if (changes.length === 0) {
                showStatus(refUpdateStatus, 'No changes detected to apply.', 'info');
                return;
            }

            applyRefChangesBtn.disabled = true;
            applyRefChangesBtn.innerHTML = '<i class="fas fa-spinner animate-spin"></i> Applying Changes...';
            refUpdateStatus.innerHTML = '';

            try {
                const apiChanges = changes.map(c => ({
                    originalSerial: c.originalSerial,
                    newSerial: c.newSerial,
                    newCustomerName: c.newCustomerName
                }));

                const response = await fetch('/api/update-device-serial', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ changes: apiChanges })
                });

                const result = await response.json();
                
                if (!response.ok) throw new Error(result.message);

                let updatedCount = 0;
                let errorCount = 0;
                let successMessage = [];

                result.changeResults.forEach((changeResult, idx) => {
                    const originalChange = changes[idx];
                    const row = originalChange.element;
                    const serialInput = row.querySelector('.ref-serial-input');
                    const errorDiv = row.querySelector(`.ref-serial-error-${idx}`); 

                    // Clear previous error state
                    serialInput.classList.remove('border-red-500');
                    if (errorDiv) errorDiv.classList.add('hidden');

                    if (changeResult.success) {
                        updatedCount++;
                        // Update the data-original attributes for successful changes
                        row.dataset.originalSerial = changeResult.newSerial;
                        row.dataset.originalName = changeResult.newCustomerName;
                        serialInput.value = changeResult.newSerial;
                        row.querySelector('.ref-name-input').value = changeResult.newCustomerName;

                    } else {
                        errorCount++;
                        // Display error message
                        serialInput.classList.add('border-red-500');
                        if (errorDiv) {
                            errorDiv.textContent = changeResult.errorMessage || 'An unknown error occurred.';
                            errorDiv.classList.remove('hidden');
                        }
                    }
                });

                if (updatedCount > 0) {
                    successMessage.push(`✅ Successfully updated ${updatedCount} reference record(s).`);
                }
                if (errorCount > 0) {
                    successMessage.push(`❌ Failed to update ${errorCount} record(s) due to errors displayed in the table.`);
                    showStatus(refUpdateStatus, successMessage.join(' '), 'danger');
                } else {
                    showStatus(refUpdateStatus, successMessage.join(' '), 'success');
                }
                
            } catch (error) {
                showStatus(refUpdateStatus, `Update Failed: ${error.message}`, 'danger');
            } finally {
                applyRefChangesBtn.disabled = false;
                applyRefChangesBtn.innerHTML = '<i class="fas fa-sync-alt"></i> Apply All Changes';
            }
        });
    }

    // 2D. INDIVIDUAL ROW UPDATE (STEP 2)
    if (refDataTableContainer) {
        refDataTableContainer.addEventListener('click', async (e) => {
            const updateBtn = e.target.closest('.update-ref-row-btn');
            if (!updateBtn) return;
            
            const row = updateBtn.closest('tr');
            if (!row) return;

            // Use the existing logic framework but apply only to the clicked row
            const originalSerial = row.dataset.originalSerial;
            const originalName = row.dataset.originalName;
            const newSerialInput = row.querySelector('.ref-serial-input');
            const newNameInput = row.querySelector('.ref-name-input');
            
            const newSerial = newSerialInput.value.trim();
            const newCustomerName = newNameInput.value.trim();
            const rowId = row.dataset.id;
            
            // Clear existing error message for this row
            const index = Array.from(row.parentNode.children).indexOf(row);
            const errorDiv = row.querySelector(`.ref-serial-error-${index}`);
            if (errorDiv) {
                errorDiv.classList.add('hidden');
                errorDiv.textContent = '';
            }
            newSerialInput.classList.remove('border-red-500');

            if (newSerial === originalSerial && newCustomerName === originalName) {
                showStatus(refUpdateStatus, `No changes detected for Meter ID ${originalSerial}.`, 'info');
                return;
            }
            
            if (newSerial === '' || newCustomerName === '') {
                showStatus(refUpdateStatus, `Device Serial ID and Customer Name cannot be empty for ID ${rowId}.`, 'danger');
                newSerialInput.classList.add('border-red-500');
                return;
            }

            const changes = [{
                originalSerial: originalSerial,
                newSerial: newSerial,
                newCustomerName: newCustomerName,
                element: row // Pass the element reference for handling response
            }];

            updateBtn.disabled = true;
            updateBtn.innerHTML = '<i class="fas fa-spinner animate-spin"></i>';
            refUpdateStatus.innerHTML = '';
            
            // Temporarily disable 'Apply All Changes' button to prevent conflicts
            if (applyRefChangesBtn) {
                applyRefChangesBtn.disabled = true;
                applyRefChangesBtn.classList.add('opacity-50', 'cursor-not-allowed');
            }

            try {
                const apiChanges = changes.map(c => ({
                    originalSerial: c.originalSerial,
                    newSerial: c.newSerial,
                    newCustomerName: c.newCustomerName
                }));

                const response = await fetch('/api/update-device-serial', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ changes: apiChanges })
                });

                const result = await response.json();
                
                if (!response.ok) throw new Error(result.message);

                const changeResult = result.changeResults[0];

                if (changeResult.success) {
                    showStatus(refUpdateStatus, `✅ Successfully updated Meter ID ${originalSerial} to ${changeResult.newSerial}.`, 'success');
                    // Update the data-original attributes for successful changes
                    row.dataset.originalSerial = changeResult.newSerial;
                    row.dataset.originalName = changeResult.newCustomerName;
                } else {
                    // Display error message
                    newSerialInput.classList.add('border-red-500');
                    if (errorDiv) {
                        errorDiv.textContent = changeResult.errorMessage || 'An unknown error occurred.';
                        errorDiv.classList.remove('hidden');
                    }
                    showStatus(refUpdateStatus, `❌ Update failed for Meter ID ${originalSerial}. See row error for details.`, 'danger');
                }
                
            } catch (error) {
                showStatus(refUpdateStatus, `Update Failed: ${error.message}`, 'danger');
            } finally {
                updateBtn.disabled = false;
                updateBtn.innerHTML = '<i class="fas fa-save"></i>';
                if (applyRefChangesBtn) {
                    applyRefChangesBtn.disabled = false;
                    applyRefChangesBtn.classList.remove('opacity-50', 'cursor-not-allowed');
                }
            }
        });
    }


    // --- 3. BILLING DATA UPLOAD (STEP 3) ---
    billingForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        toggleSpinner(processBtn, processBtnIcon, processBtnText, 'fa-spinner', 'Processing...', true);
        uploadStatus.innerHTML = '';
        
        const billMonth = billMonthInput.value;
        const tariffSar = tariffInput.value;
        
        // 1. Collect all form data (including the file 'consumption_file')
        const formData = new FormData(billingForm); 
        const uploadedFile = formData.get('consumption_file');

        // 2. File existence and size check
        if (!(uploadedFile instanceof File) || uploadedFile.size === 0) {
            showStatus(uploadStatus, 'Processing Failed: File is missing or empty. Please ensure the file is selected before clicking validate.', 'danger');
            toggleSpinner(processBtn, processBtnIcon, processBtnText, 'fa-cogs', 'Validate & Process Bills', false);
            return;
        }

        // 3. Basic form validation (Step 4 checks)
        if (!billMonth) {
            showStatus(uploadStatus, 'Please select a billing month (Step 4).', 'danger');
            toggleSpinner(processBtn, processBtnIcon, processBtnText, 'fa-cogs', 'Validate & Process Bills', false);
            return;
        }
        if (!tariffSar || parseFloat(tariffSar) <= 0) {
            showStatus(uploadStatus, 'Please enter a valid, positive tariff amount (Step 4).', 'danger');
            toggleSpinner(processBtn, processBtnIcon, processBtnText, 'fa-cogs', 'Validate & Process Bills', false);
            return;
        }


        try {
            const response = await fetch('/api/upload-billing-data', {
                method: 'POST',
                body: formData,
            });
            const result = await response.json();
            
            if (!response.ok) {
                 if (result.code === 'MISSING_REFERENCE_DATA') {
                    showStatus(uploadStatus, result.message, 'danger');
                    // Add a helpful note to fix in step 2
                    refUpdateStatus.innerHTML = `<div class="mt-2 text-sm text-red-500 font-semibold">The Meter IDs listed above must be added or corrected in Step 2: Update Reference Data.</div>`;
                 } else {
                    throw new Error(result.message);
                 }
            } else {
                // MODIFIED SUCCESS MESSAGE for better UX
                const successMsg = result.message.includes('inserted') || result.message.includes('updated') 
                    ? `Data validated against Step 1 reference list. ${result.message}`
                    : result.message;
                
                showStatus(uploadStatus, successMsg, 'success');
                // Reset fields after successful processing (Step 3 & 4)
                resetBillingFileInput();
                resetOtherCharges();
                billMonthInput.value = `${year}-${month}`; 
                
                // Prepare for Step 5
                await loadAvailableMonths(); 
                searchMonthInput.value = billMonth;
                fetchBtn.click();
            }

        } catch (error) {
            showStatus(uploadStatus, `Processing Failed: ${error.message}`, 'danger');
        } finally {
            toggleSpinner(processBtn, processBtnIcon, processBtnText, 'fa-cogs', 'Validate & Process Bills', false);
        }
    });


    // --- 4. OTHER CHARGES LOGIC (STEP 4) ---
    function resetOtherCharges() {
        if (chargesContainer) {
            chargesContainer.innerHTML = '';
        }
        if (addChargeBtn) {
            addChargeBtn.style.display = 'flex';
        }
        chargeCount = 0;
    }

    if (addChargeBtn) {
        addChargeBtn.addEventListener('click', () => {
            if (chargeCount >= 3) return;
            chargeCount++;
            const chargeEl = document.createElement('div');
            chargeEl.className = 'flex items-center gap-2';
            chargeEl.innerHTML = `
                <input type="text" name="other_charge_desc[]" placeholder="Charge #${chargeCount} Description" class="flex-1 w-full rounded-lg border-slate-300 dark:border-gray-600 bg-white dark:bg-gray-700 shadow-sm text-sm" required>
                <div class="relative">
                    <input type="number" name="other_charge_rate[]" min="0" step="0.01" placeholder="Rate" class="w-28 rounded-lg border-slate-300 dark:border-gray-600 bg-white dark:bg-gray-700 shadow-sm pl-4 pr-12 text-sm" required>
                    <span class="absolute inset-y-0 right-0 flex items-center pr-3 text-xs font-semibold text-slate-500">SAR</span>
                </div>
                <button type="button" class="remove-charge-btn text-slate-400 hover:text-red-500 text-lg font-bold">&times;</button>
            `;
            chargesContainer.appendChild(chargeEl);
            if (chargeCount >= 3) addChargeBtn.style.display = 'none';
        });
        chargesContainer.addEventListener('click', (e) => {
            if (e.target.classList.contains('remove-charge-btn')) {
                e.target.parentElement.remove();
                chargeCount--;
                addChargeBtn.style.display = 'flex';
            }
        });
    }


    // --- 5A. FETCH BILLING DATA (STEP 5) ---
    fetchBtn.addEventListener('click', async () => {
        toggleSpinner(fetchBtn, fetchBtnIcon, fetchBtnText, 'fa-spinner', 'Fetching...', true);
        fetchStatus.innerHTML = '';
        resultsTbody.innerHTML = `<tr><td colspan="24" class="px-6 py-4 text-center text-sm text-slate-500">Fetching data...</td></tr>`;
        currentBillData = [];
        downloadAllBtn.disabled = true;
        
        // Hide all buttons
        fetchBtn.classList.add('hidden');
        clearDataBtn.classList.add('hidden');
        downloadAllBtn.classList.add('hidden');

        const targetMonth = searchMonthInput.value;
        if (!targetMonth) {
            showStatus(fetchStatus, 'Please select a month to process.', 'warning');
            resultsTbody.innerHTML = `<tr><td colspan="24" class="px-6 py-4 text-center text-sm text-slate-500">No month selected.</td></tr>`;
            toggleSpinner(fetchBtn, fetchBtnIcon, fetchBtnText, 'fa-search', 'Submit', false);
            fetchBtn.classList.remove('hidden'); // Show submit button again
            return;
        }

        // Disable search month input immediately upon successful selection
        searchMonthInput.disabled = true;

        try {
            const response = await fetch('/api/get-invoicing-data', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target_month: targetMonth }),
            });
            const result = await response.json();
            if (!response.ok) throw new Error(result.message);

            if (result.status === 'info' || result.bill_data.length === 0) {
                showStatus(fetchStatus, result.message, 'info');
                resultsTbody.innerHTML = `<tr><td colspan="24" class="px-6 py-4 text-center text-sm text-slate-500">${result.message}</td></tr>`;
                // --- On Fail/No Data: Show Clear, hide Download ---
                clearDataBtn.classList.remove('hidden');
                downloadAllBtn.classList.add('hidden');
                // Re-enable input if no data is found, allowing user to change selection
                searchMonthInput.disabled = false;
                return;
            }

            currentBillData = result.bill_data;
            populateTable(currentBillData); 
            downloadAllBtn.disabled = false;
            showStatus(fetchStatus, result.message, 'success');
            
            // --- ON SUCCESS: Show Clear and Download ---
            clearDataBtn.classList.remove('hidden');
            downloadAllBtn.classList.remove('hidden');
            // Input remains disabled here

        } catch (error) {
            showStatus(fetchStatus, `Fetch Failed: ${error.message}`, 'danger');
            resultsTbody.innerHTML = `<tr><td colspan="24" class="px-6 py-4 text-center text-sm text-red-500">${error.message}</td></tr>`;
            // --- On Error: Show Clear, hide Download ---
            clearDataBtn.classList.remove('hidden');
            downloadAllBtn.classList.add('hidden');
            // Re-enable input on fetch error
            searchMonthInput.disabled = false;
        } finally {
            // --- Remove spinner, but let success/fail logic handle visibility ---
            toggleSpinner(fetchBtn, fetchBtnIcon, fetchBtnText, 'fa-search', 'Submit', false);
        }
    });
    
    // --- 5B. CLEAR DATA BUTTON LOGIC (STEP 5) ---
    if (clearDataBtn) {
        clearDataBtn.addEventListener('click', () => {
            // 1. Reset buttons
            fetchBtn.classList.remove('hidden');
            clearDataBtn.classList.add('hidden');
            downloadAllBtn.classList.add('hidden');
            downloadAllBtn.disabled = true;

            // 2. Reset data
            searchMonthInput.value = ""; // Clear dropdown
            searchMonthInput.disabled = false; // Re-enable input
            fetchStatus.innerHTML = ""; // Clear status message
            currentBillData = []; // Clear stored data
            resultsTbody.innerHTML = `
                <tr>
                    <td colspan="24" class="px-6 py-4 text-center text-sm text-slate-500">
                        No data process. Please select a month.
                    </td>
                </tr>
            `;
        });
    }
    
    // =======================================================
    // --- 5E. DOWNLOAD ALL BUTTON LOGIC (RE-ADDED) ---
    // =======================================================
    downloadAllBtn.addEventListener('click', async () => {
        if (currentBillData.length === 0) {
            showStatus(fetchStatus, 'No invoices loaded to download.', 'warning');
            return;
        }
        
        // Generate a unique progress ID
        const progressId = (window.crypto && window.crypto.randomUUID) ? window.crypto.randomUUID() : String(Date.now()) + Math.random().toString(16).slice(2);
        
        // Start spinner and disable buttons
        toggleSpinner(downloadAllBtn, downloadAllBtnIcon, downloadAllBtnText, 'fa-spinner', '0%', true);

        if (clearDataBtn) {
            clearDataBtn.disabled = true;
            clearDataBtn.classList.add('opacity-50', 'cursor-not-allowed');
        }

        // Inject progress bar UI
        let progressTrack = downloadAllBtn.querySelector('#zip-progress');
        if (!progressTrack) {
            progressTrack = document.createElement('div');
            progressTrack.id = 'zip-progress';
            progressTrack.className = 'relative w-full h-2 bg-slate-200 rounded overflow-hidden mt-2';
            const progressFill = document.createElement('div');
            progressFill.id = 'zip-progress-fill';
            progressFill.className = 'absolute left-0 top-0 h-full bg-green-500';
            progressFill.style.width = '0%';
            progressTrack.appendChild(progressFill);
            downloadAllBtn.appendChild(progressTrack);
        }
        const progressFillEl = downloadAllBtn.querySelector('#zip-progress-fill');
        let pollTimer = null;

        // Start polling the server for progress
        const startPolling = () => {
            pollTimer = setInterval(async () => {
                try {
                    const resp = await fetch(`/api/bulk-progress/${progressId}`);
                    if (!resp.ok) return; 
                    const { processed, total, done } = await resp.json();
                    const pct = total > 0 ? Math.floor((processed / total) * 100) : 0;
                    
                    if(downloadAllBtnText) downloadAllBtnText.textContent = `${pct}%`;
                    if (progressFillEl) progressFillEl.style.width = pct + '%'; // Fixed variable name
                    
                    if (done) {
                        clearInterval(pollTimer);
                    }
                } catch (e) {
                    // Ignore polling errors
                }
            }, 500);
        };
        startPolling();

        try {
            // Send the request to the server to start ZIP creation
            const response = await fetch('/api/download-invoices', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ bill_data: currentBillData, progressId }),
            });
            
            if (!response.ok) {
                 // Throw error to be caught in catch block below
                 const errorText = await response.text(); 
                 throw new Error(`Server error creating ZIP: ${errorText.substring(0, 50)}...`);
            }
            
            // Handle successful download (receive ZIP file)
            const blob = await response.blob();
            const month = currentBillData[0].upload_month || 'unknown';
            const filename = `Invoice_Bulk_${month}.zip`;
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            a.remove();
            
            showStatus(fetchStatus, `✅ Successfully downloaded ${currentBillData.length} invoices.`, 'success');

        } catch (error) {
            showStatus(fetchStatus, `Download Failed: ${error.message}`, 'danger');
        } finally {
            if (pollTimer) clearInterval(pollTimer);
            toggleSpinner(downloadAllBtn, downloadAllBtnIcon, downloadAllBtnText, 'fa-file-archive', 'Download All Bills', false);
            
            // Cleanup progress bar
            const track = downloadAllBtn.querySelector('#zip-progress');
            if (track) track.remove();
            
            // Re-enable Clear button
            if (clearDataBtn) {
                clearDataBtn.disabled = false;
                clearDataBtn.classList.remove('opacity-50', 'cursor-not-allowed');
            }
        }
    });
    // =======================================================
    // --- HELPER: Format YYYY-MM to MonthName YYYY ---
    function formatBillingMonth(monthString) {
        if (!monthString || monthString.length !== 7 || monthString.indexOf('-') === -1) {
            return monthString; 
        }
        
        try {
            const [year, monthNum] = monthString.split('-');
            // Month number is 1-based, Date constructor uses 0-based
            const date = new Date(year, monthNum - 1, 1);
            
            // Return full month name and year
            const monthName = date.toLocaleString('default', { month: 'long' });
            return `${monthName} ${year}`;
        } catch (e) {
            return monthString;
        }
    }    
    // --- 5C. POPULATE RESULTS TABLE (STEP 5) ---
    function populateTable(bills) {
        const settings = loadColumnSettings();
        resultsTbody.innerHTML = ''; 
        bills.forEach((bill, index) => {
            const style = (key) => settings[key] ? '' : 'style="display: none;"';
            
            const row = `
                <tr class="hover:bg-slate-50 dark:hover:bg-gray-700">
                    <td data-column="col-id" ${style('col-id')} class="whitespace-nowrap py-4 pl-6 pr-3 text-sm font-medium text-slate-900 dark:text-white">${bill.id}</td>
                    <td data-column="col-serial" ${style('col-serial')} class="whitespace-nowrap px-3 py-4 text-sm text-slate-500 dark:text-slate-300">${bill.device_serialno}</td>
                    <td data-column="col-customer" ${style('col-customer')} class="whitespace-nowrap px-3 py-4 text-sm text-slate-500 dark:text-slate-300">${bill.customer_name}</td>
                    <td data-column="col-consumption" ${style('col-consumption')} class="whitespace-nowrap px-3 py-4 text-sm text-slate-500 dark:text-slate-300">${parseFloat(bill.net_consumption_m3).toFixed(2)} m³</td>
                    <td data-column="col-total" ${style('col-total')} class="whitespace-nowrap px-3 py-4 text-sm font-semibold text-slate-600 dark:text-slate-200">SAR ${parseFloat(bill.total_bill_amount_sar).toFixed(2)}</td>
                    <td data-column="col-bill-month" ${style('col-bill-month')} class="whitespace-nowrap px-3 py-4 text-sm text-slate-500 dark:text-slate-300">${formatBillingMonth(bill.upload_month)}</td>
                    <td data-column="col-tariff" ${style('col-tariff')} class="whitespace-nowrap px-3 py-4 text-sm text-slate-500 dark:text-slate-300">${parseFloat(bill.upload_tariff_sar).toFixed(2)}</td>
                    <td data-column="col-vat" ${style('col-vat')} class="whitespace-nowrap px-3 py-4 text-sm text-slate-500 dark:text-slate-300">${parseFloat(bill.vat_percent).toFixed(2)}%</td>
                    <td data-column="col-cust-hash" ${style('col-cust-hash')} class="whitespace-nowrap px-3 py-4 text-sm text-slate-500 dark:text-slate-300">${bill.customer_hash}</td>
                    <td data-column="col-bldg-hash" ${style('col-bldg-hash')} class="whitespace-nowrap px-3 py-4 text-sm text-slate-500 dark:text-slate-300">${bill.building_hash}</td>
                    <td data-column="col-apt-hash" ${style('col-apt-hash')} class="whitespace-nowrap px-3 py-4 text-sm text-slate-500 dark:text-slate-300">${bill.apartment_hash}</td>
                    <td data-column="col-start-date" ${style('col-start-date')} class="whitespace-nowrap px-3 py-4 text-sm text-slate-500 dark:text-slate-300">${formatDate(bill.bill_start_date)}</td>
                    <td data-column="col-end-date" ${style('col-end-date')} class="whitespace-nowrap px-3 py-4 text-sm text-slate-500 dark:text-slate-300">${formatDate(bill.bill_end_date)}</td>
                    <td data-column="col-inv-date" ${style('col-inv-date')} class="whitespace-nowrap px-3 py-4 text-sm text-slate-500 dark:text-slate-300">${formatDate(bill.invoice_date_csv)}</td>
                    <td data-column="col-read-time" ${style('col-read-time')} class="whitespace-nowrap px-3 py-4 text-sm text-slate-500 dark:text-slate-300">${formatDate(bill.final_reading_timestamp)}</td>
                    <td data-column="col-read-vol" ${style('col-read-vol')} class="whitespace-nowrap px-3 py-4 text-sm text-slate-500 dark:text-slate-300">${parseFloat(bill.final_reading_volume_m3).toFixed(2)}</td>
                    <td data-column="col-c1-desc" ${style('col-c1-desc')} class="whitespace-nowrap px-3 py-4 text-sm text-slate-500 dark:text-slate-300">${bill.csv_charge_1_desc || 'N/A'}</td>
                    <td data-column="col-c1-rate" ${style('col-c1-rate')} class="whitespace-nowrap px-3 py-4 text-sm text-slate-500 dark:text-slate-300">${parseFloat(bill.csv_charge_1_rate).toFixed(2)}</td>
                    <td data-column="col-c2-desc" ${style('col-c2-desc')} class="whitespace-nowrap px-3 py-4 text-sm text-slate-500 dark:text-slate-300">${bill.csv_charge_2_desc || 'N/A'}</td>
                    <td data-column="col-c2-rate" ${style('col-c2-rate')} class="whitespace-nowrap px-3 py-4 text-sm text-slate-500 dark:text-slate-300">${parseFloat(bill.csv_charge_2_rate).toFixed(2)}</td>
                    <td data-column="col-c3-desc" ${style('col-c3-desc')} class="whitespace-nowrap px-3 py-4 text-sm text-slate-500 dark:text-slate-300">${bill.csv_charge_3_desc || 'N/A'}</td>
                    <td data-column="col-c3-rate" ${style('col-c3-rate')} class="whitespace-nowrap px-3 py-4 text-sm text-slate-500 dark:text-slate-300">${parseFloat(bill.csv_charge_3_rate).toFixed(2)}</td>
                    
                    <td data-column="col-actions" ${style('col-actions')} class="relative whitespace-nowrap py-4 pl-3 pr-6 text-right text-sm font-medium">
                        <button class="view-details-btn text-blue-600 dark:text-blue-400 hover:underline text-sm font-medium mr-4" data-index="${index}" title="See More Details">
                            View
                        </button>
                        <button class="download-single-btn text-red-600 hover:text-red-900" data-index="${index}" title="Download PDF">
                            <i class="fas fa-file-pdf text-lg"></i>
                        </button>
                    </td>

                    <td class="sticky right-0 bg-white dark:bg-gray-800 p-4"></td>
                </tr>
            `;
            resultsTbody.insertAdjacentHTML('beforeend', row);
        });
    }

    // --- 5D. TABLE ACTIONS (DOWNLOAD SINGLE / VIEW DETAILS) ---
    resultsTbody.addEventListener('click', async (e) => {
        const viewBtn = e.target.closest('.view-details-btn');
        if (viewBtn) {
            const index = viewBtn.dataset.index;
            const bill = currentBillData[index];
            // Since populateAndShowModal is defined later, assuming it works as intended
            // We'll proceed with the assumption it works unless the user reports modal issues
            populateAndShowModal(bill);
            return; 
        }
        const downloadBtn = e.target.closest('.download-single-btn');
        if (downloadBtn) {
            const originalIcon = downloadBtn.innerHTML;
            downloadBtn.disabled = true;
            downloadBtn.innerHTML = '<i class="fas fa-spinner animate-spin text-lg"></i>';
            try {
                const index = downloadBtn.dataset.index;
                const bill = currentBillData[index];
                const response = await fetch('/api/download-single-invoice', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ bill_data: bill }),
                });
                if (!response.ok) throw new Error('Server error creating PDF.');
                const blob = await response.blob();
                const filename = `Invoice_${bill.device_serialno}_${bill.upload_month}.pdf`;
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.style.display = 'none';
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                a.remove();
            } catch (error) {
                showStatus(fetchStatus, `Download Failed: ${error.message}`, 'danger');
            } finally {
                downloadBtn.disabled = false;
                downloadBtn.innerHTML = originalIcon;
            }
        }
    });


    // --- 5E. MODAL FUNCTIONS ---
    function populateAndShowModal(bill) {
        // ... (Modal logic remains unchanged, omitted for brevity)
        const consumption = parseFloat(bill.net_consumption_m3);
        const tariff = parseFloat(bill.upload_tariff_sar);
        const vat_percent = parseFloat(bill.vat_percent);
        const consumption_charge = consumption * tariff;
        let total_other_charges = 0;
        const charges = [];
        if (bill.csv_charge_1_rate > 0) {
            const rate = parseFloat(bill.csv_charge_1_rate);
            charges.push({ desc: bill.csv_charge_1_desc, rate: rate });
            total_other_charges += rate;
        }
        if (bill.csv_charge_2_rate > 0) {
            const rate = parseFloat(bill.csv_charge_2_rate);
            charges.push({ desc: bill.csv_charge_2_desc, rate: rate });
            total_other_charges += rate;
        }
        if (bill.csv_charge_3_rate > 0) {
            const rate = parseFloat(bill.csv_charge_3_rate);
            charges.push({ desc: bill.csv_charge_3_desc, rate: rate });
            total_other_charges += rate;
        }
        const subtotal = consumption_charge + total_other_charges;
        const vat_amount = subtotal * (vat_percent / 100);
        const total_bill = parseFloat(bill.total_bill_amount_sar);
        let chargesHtml = '';
        if (charges.length > 0) {
            charges.forEach(charge => {
                chargesHtml += `
                    <tr>
                        <td class="py-2 pr-4 text-slate-500 dark:text-slate-400">${charge.desc}</td>
                        <td class="py-2 text-right font-medium text-slate-700 dark:text-slate-300">SAR ${charge.rate.toFixed(2)}</td>
                    </tr>
                `;
            });
        } else {
            chargesHtml = `
                <tr>
                    <td class="py-2 pr-4 text-slate-500 dark:text-slate-400">No Other Charges</td>
                    <td class="py-2 text-right font-medium text-slate-700 dark:text-slate-300">SAR 0.00</td>
                </tr>
            `;
        }
        modalDetailsContainer.innerHTML = `
            <div class="pb-4 border-b border-slate-200 dark:border-gray-700">
                <h4 class="text-lg font-semibold text-slate-800 dark:text-white mb-3">Customer Information</h4>
                <div class="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                    <div class="font-medium text-slate-500 dark:text-slate-400">Customer Name:</div>
                    <div class="text-slate-700 dark:text-slate-300">${bill.customer_name}</div>
                    <div class="font-medium text-slate-500 dark:text-slate-400">Customer ID:</div>
                    <div class="text-slate-700 dark:text-slate-300">${bill.customer_hash}</div>
                    <div class="font-medium text-slate-500 dark:text-slate-400">Building / Apt:</div>
                    <div class="text-slate-700 dark:text-slate-300">${bill.building_hash} / ${bill.apartment_hash}</div>
                    <div class="font-medium text-slate-500 dark:text-slate-400">Device Serial ID:</div>
                    <div class="text-slate-700 dark:text-slate-300">${bill.device_serialno}</div>
                </div>
            </div>
            <div class="py-4 border-b border-slate-200 dark:border-gray-700">
                <h4 class="text-lg font-semibold text-slate-800 dark:text-white mb-3">Billing Period</h4>
                <div class="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                    <div class="font-medium text-slate-500 dark:text-slate-400">Invoice Date:</div>
                    <div class="text-slate-700 dark:text-slate-300">${formatDate(bill.invoice_date_csv)}</div>
                    <div class="font-medium text-slate-500 dark:text-slate-400">Billing Month:</div>
                    <div class="text-slate-700 dark:text-slate-300">${bill.upload_month}</div>
                    <div class="font-medium text-slate-500 dark:text-slate-400">Period Start:</div>
                    <div class="text-slate-700 dark:text-slate-300">${formatDate(bill.bill_start_date)}</div>
                    <div class="font-medium text-slate-500 dark:text-slate-400">Period End:</div>
                    <div class="text-slate-700 dark:text-slate-300">${formatDate(bill.bill_end_date)}</div>
                </div>
            </div>
            <div>
                <h4 class="text-lg font-semibold text-slate-800 dark:text-white mb-3">Bill Calculation</h4>
                <table class="w-full text-sm">
                    <tbody>
                        <tr>
                            <td class="py-2 pr-4 text-slate-500 dark:text-slate-400">
                                Consumption (${consumption.toFixed(2)} m³ @ ${tariff.toFixed(2)} SAR)
                            </td>
                            <td class="py-2 text-right font-medium text-slate-700 dark:text-slate-300">SAR ${consumption_charge.toFixed(2)}</td>
                        </tr>
                        ${chargesHtml}
                        <tr class="border-t border-slate-200 dark:border-gray-600">
                            <td class="pt-3 pr-4 font-semibold text-slate-600 dark:text-slate-200">Subtotal</td>
                            <td class="pt-3 text-right font-semibold text-slate-700 dark:text-slate-200">SAR ${subtotal.toFixed(2)}</td>
                        </tr>
                        <tr>
                            <td class="py-2 pr-4 text-slate-500 dark:text-slate-400">VAT (${vat_percent.toFixed(2)}%)</td>
                            <td class="py-2 text-right font-medium text-slate-700 dark:text-slate-300">SAR ${vat_amount.toFixed(2)}</td>
                        </tr>
                        <tr class="border-t-2 border-slate-300 dark:border-gray-500">
                            <td class="pt-3 pr-4 text-lg font-bold text-red-600">Total Bill Amount</td>
                            <td class="pt-3 text-right text-lg font-bold text-red-600">SAR ${total_bill.toFixed(2)}</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        `;
        modal.classList.remove('hidden');
    }
    function hideModal() {
        modal.classList.add('hidden');
        modalDetailsContainer.innerHTML = ''; // Clear content
    }
    modalCloseBtn.addEventListener('click', hideModal);
    modalBackdrop.addEventListener('click', hideModal);


    // --- 5F. COLUMN TOGGLE LOGIC (STEP 5) ---
    // (This function is unchanged)
    const defaultColumnSettings = {
        'col-id': true, 'col-serial': true, 'col-customer': true, 'col-consumption': true, 'col-total': true, 'col-actions': true,
        'col-bill-month': false, 'col-tariff': false, 'col-vat': false, 'col-cust-hash': false, 'col-bldg-hash': false,
        'col-apt-hash': false, 'col-start-date': false, 'col-end-date': false, 'col-inv-date': false, 'col-read-time': false,
        'col-read-vol': false, 'col-c1-desc': false, 'col-c1-rate': false, 'col-c2-desc': false, 'col-c2-rate': false,
        'col-c3-desc': false, 'col-c3-rate': false
    };
    function saveColumnSettings(settings) {
        localStorage.setItem(COLUMN_SETTINGS_KEY, JSON.stringify(settings));
    }
    function loadColumnSettings() {
        const saved = localStorage.getItem(COLUMN_SETTINGS_KEY);
        if (saved) {
            return { ...defaultColumnSettings, ...JSON.parse(saved) }; 
        }
        return defaultColumnSettings;
    }
    function applyColumnSettings(settings) {
        if (!colToggleMenu || !billTable) return;
        const checkboxes = colToggleMenu.querySelectorAll('input[type="checkbox"]');
        checkboxes.forEach(cb => {
            const columnKey = cb.dataset.column;
            cb.checked = settings[columnKey] || false;
        });
        const headers = billTable.querySelectorAll('thead th'); 
        headers.forEach(th => {
            const columnKey = th.dataset.column;
            if (columnKey) { 
                th.style.display = settings[columnKey] ? '' : 'none';
            }
        });
        const cells = billTable.querySelectorAll('tbody td');
        cells.forEach(td => {
            const columnKey = td.dataset.column;
            if (columnKey) { 
                td.style.display = settings[columnKey] ? '' : 'none';
            }
        });
    }
    if (colToggleBtn && colToggleMenu && billTable) {
        const initialSettings = loadColumnSettings();
        applyColumnSettings(initialSettings); 
        colToggleBtn.addEventListener('click', (e) => {
            e.stopPropagation(); 
            colToggleMenu.classList.toggle('hidden');
        });
        document.addEventListener('click', (e) => {
            if (!colToggleMenu.classList.contains('hidden') && !colToggleMenu.contains(e.target) && !colToggleBtn.contains(e.target)) {
                colToggleMenu.classList.add('hidden');
            }
        });
        colToggleMenu.addEventListener('change', (e) => {
            if (e.target.type === 'checkbox') {
                const columnKey = e.target.dataset.column; 
                const isChecked = e.target.checked;
                const settings = loadColumnSettings();
                settings[columnKey] = isChecked;
                saveColumnSettings(settings);
                applyColumnSettings(settings);
            }
        });
    }


    // --- 5G. DYNAMIC MONTH LOADER (STEP 5) ---
    async function loadAvailableMonths() {
        if (!searchMonthInput) return; 
        try {
            const response = await fetch('/api/get-available-months');
            if (!response.ok) {
                searchMonthInput.innerHTML = '<option value="">Error loading months</option>';
                return;
            }
            const data = await response.json();
            if (data.status === 'success' && data.months.length > 0) {
                searchMonthInput.innerHTML = '<option value=""></option>'; 
                data.months.forEach(monthValue => { 
                    const option = document.createElement('option');
                    option.value = monthValue;
                    try {
                        const [year, monthNum] = monthValue.split('-');
                        const date = new Date(year, monthNum - 1, 1);
                        const monthName = date.toLocaleString('default', { month: 'long' });
                        option.textContent = `${monthName} ${year}`;
                    } catch (e) {
                        option.textContent = monthValue; 
                    }
                    searchMonthInput.appendChild(option);
                });
            } else {
                searchMonthInput.innerHTML = '<option value="">No billing data found</option>';
            }
        } catch (error) {
            console.error('Failed to fetch available months:', error);
            searchMonthInput.innerHTML = '<option value="">Error loading months</option>';
        }
    }
    
    // --- NEW: Tab Event Listeners ---
    if (tabMasterBtn) {
        tabMasterBtn.addEventListener('click', () => switchTab('master'));
    }
    if (tabBillingBtn) {
        tabBillingBtn.addEventListener('click', () => {
            if (step1Complete) {
                switchTab('billing');
            }
        });
    }

    // Initial load calls
    loadReferenceData(); // Start by loading step 2 data to check if step 1 is complete
    loadAvailableMonths(); // Load step 5 months for when step 1 is complete
    updateStepVisibility(); // Set initial state
    switchTab('master'); // Start on the master tab
});