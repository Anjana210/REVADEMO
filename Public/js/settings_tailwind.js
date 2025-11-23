document.addEventListener('DOMContentLoaded', () => {
    // --- Main Tab Switching Logic ---
    const tabs = document.querySelectorAll('.tab-link');
    const contents = document.querySelectorAll('.tab-content');
    
    // Define classes for active (light red bg) and inactive (default) states
    const activeClasses = [
        'bg-blue-100',          // Match sidebar active background
        'text-blue-700',        // Match sidebar active text
        'dark:bg-gray-700',     // Match sidebar dark background
        'dark:text-white',      // Match sidebar dark text
        'rounded-lg',
        'border-b-0'
    ];
    const inactiveClasses = [
        'text-slate-500', 
        'dark:text-slate-400',
        'border-b-2',           // <-- FIX: Keep bottom border
        'border-transparent'    // <-- FIX: Make it transparent
    ];
    
    // Define ALL possible active classes (from previous versions) to ensure they are removed
    const allPossibleActiveClasses = [
        // Current desired
        'bg-blue-100', 'text-blue-700', 'dark:bg-gray-700', 'dark:text-white', 'rounded-lg', 'border-b-0',
        // Remove previous blue variants
        'bg-blue-50', 'dark:bg-blue-900/40', 'dark:text-blue-300',
        'dark:bg-blue-900/60', 'dark:text-blue-400',
        // Old blue attempts
        'border-blue-500', 'text-blue-600', 'dark:text-blue-400',
        // Old "solid red" style
        'bg-red-600', 'text-white', 'dark:text-white', 'border-red-600',
        // Original "red line" style
        'border-red-500', 'text-red-600', 'dark:text-red-400',
        // 3D "connected" style
        'bg-white', 'dark:bg-gray-800', 'border-slate-200', 'dark:border-gray-700', 
        'border-t', 'border-l', 'border-r', 'rounded-t-lg', 'border-b-white', 'dark:border-b-gray-800'
    ];


    tabs.forEach(tab => {
        tab.addEventListener('click', (e) => {
            e.preventDefault();
            
            // Get target content ID
            const targetId = tab.id.replace('tab-', 'content-');
            
            // Update tab styles
            tabs.forEach(t => {
                // Remove ALL possible active classes from all tabs
                t.classList.remove(...allPossibleActiveClasses);
                
                // Add inactive classes to all tabs
                t.classList.add(...inactiveClasses);
            });
            
            // Add new active classes to the clicked tab
            tab.classList.add(...activeClasses);
            // Remove inactive classes from the clicked tab
            tab.classList.remove(...inactiveClasses);
            
            // Show/hide content
            contents.forEach(content => { content.classList.toggle('hidden', content.id !== targetId); });
            
            // Toggle save company button visibility
            const toggleSaveBtnVisibility = () => {
                const rolesContent = document.getElementById('content-roles');
                const isRolesActive = rolesContent && !rolesContent.classList.contains('hidden');
                if (saveCompanyBtn) saveCompanyBtn.classList.toggle('hidden', isRolesActive);
            };
            toggleSaveBtnVisibility();

            // If System Settings tab is opened, load health snapshot
            if (tab.id === 'tab-settings') {
                if (typeof loadHealth === 'function') loadHealth();
            }
        });
    });

    // Set initial active tab from query (?tab=roles) or default to company
    const params = new URLSearchParams(window.location.search);
    const tabParam = params.get('tab');
    const initialTabId = tabParam === 'roles' ? 'tab-roles' : (tabParam === 'settings' ? 'tab-settings' : 'tab-company');
    const initialTab = document.getElementById(initialTabId);
    if (initialTab) initialTab.click();

    // --- System Health: helpers ---
    function setStatus(key, status, extraLabel) {
        const li = document.querySelector(`#health-list li[data-key="${key}"]`);
        if (!li) return;
        const box = li.querySelector('.health-status');
        const label = box ? box.querySelector('.label') : null;
        if (!box || !label) return;
        const classes = ['text-green-600','text-yellow-600','text-red-600','text-slate-500'];
        box.classList.remove(...classes);
        let cls = 'text-slate-500';
        let text = 'Unknown';
        switch (status) {
            case 'healthy': cls = 'text-green-600'; text = 'Healthy'; break;
            case 'operational': cls = 'text-green-600'; text = 'Operational'; break;
            case 'secure': cls = 'text-green-600'; text = 'Secure'; break;
            case 'degraded':
            case 'attention': cls = 'text-yellow-600'; text = (status === 'attention' ? 'Attention' : 'Degraded'); break;
            case 'down': cls = 'text-red-600'; text = 'Down'; break;
            default: cls = 'text-slate-500'; text = 'Unknown';
        }
        box.classList.add(cls);
        label.textContent = extraLabel ? extraLabel : text;
    }

    async function loadHealth() {
        try {
            const res = await fetch('/api/customer-health');
            if (!res.ok) throw new Error('Failed to fetch');
            const json = await res.json();
            const d = json && json.data ? json.data : {};
            setStatus('core_service', d.core_service?.status);
            setStatus('bill_engine', d.bill_engine?.status === 'operational' ? 'operational' : d.bill_engine?.status);
            // Pending jobs shows value text
            const pjVal = (d.pending_jobs && typeof d.pending_jobs.value === 'number') ? d.pending_jobs.value : 0;
            setStatus('pending_jobs', d.pending_jobs?.status, `${pjVal} Waiting`);
            // Avg processing shows label text
            setStatus('avg_processing', d.avg_processing?.status, d.avg_processing?.label || '-');
            setStatus('security', d.security?.status);
        } catch (e) {
            console.warn('Health load failed:', e.message);
        }
    }

    async function refreshHealth() {
        const btn = document.getElementById('health-refresh-btn');
        if (btn) { btn.disabled = true; btn.textContent = 'Refreshing...'; }
        try {
            // For customer-health we simply reload snapshot (no heavy recompute)
            await loadHealth();
        } catch (e) {
            alert('Failed to refresh system health');
        } finally {
            if (btn) { btn.disabled = false; btn.textContent = 'Refresh'; }
        }
    }

    // Bind refresh button and initial load if settings content is visible
    const healthBtn = document.getElementById('health-refresh-btn');
    if (healthBtn) healthBtn.addEventListener('click', refreshHealth);
    const settingsContent = document.getElementById('content-settings');
    if (settingsContent && !settingsContent.classList.contains('hidden')) {
        loadHealth();
    }

    const rolesTable = document.getElementById('roles-table');
    if (rolesTable) {
        rolesTable.addEventListener('click', (e) => {
            const link = e.target.closest('.edit-user-link');
            if (!link) return;
            e.preventDefault();
            const role = link.getAttribute('data-role');
            const currentUsername = link.getAttribute('data-username') || '';

            const title = role === 'master' ? 'Edit Master Account' : 'Edit Operator Account';
            const content = `
                <form id="edit-user-form" class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium mb-1">Username</label>
                        <input id="edit-username" name="username" type="text" value="${currentUsername}" required class="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-gray-700" />
                    </div>
                    <div>
                        <label class="block text-sm font-medium mb-1">Password (optional)</label>
                        <input id="edit-password" name="password" type="password" placeholder="••••••••" class="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-gray-700" />
                    </div>
                </form>`;

            openModal(title, content, 'Save', () => {
                const u = document.getElementById('edit-username').value.trim();
                const p = document.getElementById('edit-password').value;
                if (!u) { alert('Username is required'); return; }
                const form = document.createElement('form');
                form.method = 'POST';
                form.action = `/admin/users/${role}`;
                const inU = document.createElement('input'); inU.type='hidden'; inU.name='username'; inU.value=u; form.appendChild(inU);
                if (p) { const inP = document.createElement('input'); inP.type='hidden'; inP.name='password'; inP.value=p; form.appendChild(inP); }
                document.body.appendChild(form);
                form.submit();
            });
        });
    }

    // --- Modal Handling ---
    const genericModal = document.getElementById('generic-modal');
    const modalContent = document.getElementById('modal-content');
    const modalTitle = document.getElementById('modal-title');
    const modalBody = document.getElementById('modal-body');
    const modalActionBtn = document.getElementById('modal-action-btn');
    let currentModalAction = null;
    
    const openModal = (title, content, actionText, actionCallback, size = 'md') => {
        modalTitle.textContent = title;
        modalBody.innerHTML = content;
        modalActionBtn.textContent = actionText;
        currentModalAction = actionCallback;
        
        modalContent.classList.remove('max-w-md', 'max-w-4xl');
        if(size === 'lg') {
            modalContent.classList.add('max-w-4xl');
        } else {
            modalContent.classList.add('max-w-md');
        }

        genericModal.classList.remove('hidden');
        genericModal.classList.add('flex');
    };
    
    const closeModal = () => {
        genericModal.classList.add('hidden');
        genericModal.classList.remove('flex');
        currentModalAction = null;
    };
    
    if (genericModal) {
        genericModal.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal-backdrop') || e.target.closest('.modal-close-btn')) {
                closeModal();
            }
        });
    }
    
    if (modalActionBtn) {
        modalActionBtn.addEventListener('click', () => {
            if (currentModalAction) {
                currentModalAction();
            }
        });
    }


    // --- System Settings Functionality (Old) ---
    const saveSettingsBtn = document.getElementById('save-settings-btn');
    if (saveSettingsBtn) {
        saveSettingsBtn.addEventListener('click', (e) => {
            const btn = e.target;
            btn.textContent = 'Saved!';
            btn.classList.add('bg-green-600', 'hover:bg-green-700');
            btn.classList.remove('bg-red-600', 'hover:bg-red-700');
            
            setTimeout(() => {
                btn.textContent = 'Save Settings';
                btn.classList.remove('bg-green-600', 'hover:bg-green-700');
                btn.classList.add('bg-red-600', 'hover:bg-red-700');
            }, 2000);
        });
    }

    const logoUploadInput = document.getElementById('logo-upload');
    const logoPreview = document.getElementById('logo-preview');
    
    if (logoUploadInput && logoPreview) {
        logoUploadInput.addEventListener('change', () => {
            if (logoUploadInput.files && logoUploadInput.files[0]) {
                const reader = new FileReader();
                reader.onload = (e) => {
                    logoPreview.src = e.target.result;
                 };
                reader.readAsDataURL(logoUploadInput.files[0]);
            }
        });
    }

    const manageTemplatesBtn = document.getElementById('manage-templates-btn');
    if (manageTemplatesBtn) {
        manageTemplatesBtn.addEventListener('click', () => {
            openModal('Manage Templates', '<p>This is where you would edit email, invoice, and notification templates.</p>', 'Save Changes', () => { alert('Template changes saved!'); closeModal(); });
        });
    }


    // --- NEW: COMPANY DETAILS LOGIC ---
    const companyForm = document.getElementById('company-settings-form');
    const companyLogoUpload = document.getElementById('company-logo-upload');
    const companyLogoPreview = document.getElementById('company-logo-preview');
    const saveCompanyBtn = document.getElementById('save-company-btn');
    const removeLogoBtn = document.getElementById('remove-logo-btn'); // <-- ADDED

    // 1. Load data on page load
    async function loadCompanySettings() {
        try {
            const response = await fetch('/api/company-settings');
            const result = await response.json();
            
            if (result.status === 'success') {
                const data = result.data;
                
                // Helper to safely set value
                const setValue = (id, value) => {
                    const el = document.getElementById(id);
                    if (el) {
                        el.value = value || '';
                    }
                };

                // --- Company Details Tab ---
                setValue('company_name', data.company_name);
                setValue('address', data.address);
                setValue('city', data.city);
                setValue('postal_code', data.postal_code);
                setValue('phone', data.phone);
                setValue('email', data.email);
                setValue('website', data.website);
                setValue('about', data.about);
                
                // --- System Settings Tab (NEW) ---
                setValue('default_language', data.default_language);
                setValue('currency', data.currency);
                setValue('vat_rate', data.vat_rate);
                setValue('license_type', data.license_type);
                setValue('license_status', data.license_status);
                
                // --- ADDED LINES ---
                setValue('number_of_devices', data.number_of_devices);

                // Format the expiry date for display (YYYY-MM-DD)
                if (data.expiry_date) {
                    const date = new Date(data.expiry_date);
                    const formattedDate = date.toISOString().split('T')[0];
                    setValue('expiry_date', formattedDate);
                } else {
                    setValue('expiry_date', '');
                }
                // --- END OF ADDED LINES ---
                
                // Logo preview and sidebar logo
                if (data.logo_url) {
                    companyLogoPreview.src = data.logo_url;
                    document.getElementById('existing-logo-url').value = data.logo_url;

                    // --- Update Sidebar on Load ---
                    const sidebarImage = document.getElementById('sidebar-logo-image');
                    const sidebarText = document.getElementById('sidebar-logo-text');
                    if (sidebarImage && sidebarText) {
                        sidebarImage.src = data.logo_url;
                        sidebarImage.classList.remove('hidden');
                        sidebarText.classList.add('hidden');
                    }
                    // --- End Sidebar Update ---

                    // Show the remove button
                    if (removeLogoBtn) removeLogoBtn.classList.remove('hidden');

                } else {
                    // --- Ensure Sidebar is Text if no logo ---
                    const sidebarImage = document.getElementById('sidebar-logo-image');
                    const sidebarText = document.getElementById('sidebar-logo-text');
                    if (sidebarImage && sidebarText) {
                        sidebarImage.src = '';
                        sidebarImage.classList.add('hidden');
                        sidebarText.classList.remove('hidden');
                    }
                    // --- End Sidebar Update ---
                }
            } else {
                console.error('Error loading settings: ' + result.message);
            }
        } catch (e) {
            console.error('Failed to load company settings. ' + e.message);
        }
    }
    
    // 2. Handle new logo preview
    if (companyLogoUpload && companyLogoPreview) {
        companyLogoUpload.addEventListener('change', () => {
            if (companyLogoUpload.files && companyLogoUpload.files[0]) {
                const reader = new FileReader();
                reader.onload = (e) => {
                    const newLogoSrc = e.target.result;

                    // 1. Update the preview image on the settings page
                    companyLogoPreview.src = newLogoSrc;

                    // 2. Find the sidebar elements
                    const sidebarImage = document.getElementById('sidebar-logo-image');
                    const sidebarText = document.getElementById('sidebar-logo-text');

                    // 3. Update the sidebar
                    if (sidebarImage && sidebarText) {
                        sidebarImage.src = newLogoSrc;
                        sidebarImage.classList.remove('hidden');
                        sidebarText.classList.add('hidden');
                    }

                    // 4. Show the remove button
                    if (removeLogoBtn) removeLogoBtn.classList.remove('hidden');
                };
                reader.readAsDataURL(companyLogoUpload.files[0]);
            }
        });
    }

    // 3. Handle logo removal
    if (removeLogoBtn) {
        removeLogoBtn.addEventListener('click', () => {
            // 1. Reset preview to placeholder
            const placeholder = 'https://placehold.co/150x150/ef4444/white?text=Logo';
            companyLogoPreview.src = placeholder;
            
            // 2. Clear the hidden input to tell backend to remove logo
            document.getElementById('existing-logo-url').value = '';
            // 3. Clear the file input in case a file was selected but not saved
            companyLogoUpload.value = '';

            // 4. Reset the sidebar
            const sidebarImage = document.getElementById('sidebar-logo-image');
            const sidebarText = document.getElementById('sidebar-logo-text');
            if (sidebarImage && sidebarText) {
                sidebarImage.src = '';
                sidebarImage.classList.add('hidden');
                sidebarText.classList.remove('hidden');
            }

            // 5. Hide the remove button itself
            removeLogoBtn.classList.add('hidden');
        });
    }

    // 4. Handle form submission
if (companyForm) {
    companyForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const btnText = saveCompanyBtn.innerHTML;
        saveCompanyBtn.innerHTML = `<i class="fas fa-spinner animate-spin mr-2"></i> Saving...`;
        saveCompanyBtn.disabled = true;

        const formData = new FormData(companyForm);

        try {
            const response = await fetch('/api/company-settings', {
                method: 'POST',
                body: formData
            });

            const result = await response.json();

            if (result.status === 'success') {

                // --- THIS IS THE NEW LINE ---
                location.reload(); 
                // --- END OF NEW LINE ---

                // The rest of this code will not run because the page reloads,
                // but that is okay because the reload will show all the new data.
                if(result.newLogoUrl) {
                    document.getElementById('existing-logo-url').value = result.newLogoUrl;
                    companyLogoPreview.src = result.newLogoUrl;

                    // --- Update sidebar on save (if new URL) ---
                    const sidebarImage = document.getElementById('sidebar-logo-image');
                    const sidebarText = document.getElementById('sidebar-logo-text');
                    if (sidebarImage && sidebarText) {
                        sidebarImage.src = result.newLogoUrl;
                        sidebarImage.classList.remove('hidden');
                        sidebarText.classList.add('hidden');
                    }
                    if (removeLogoBtn) removeLogoBtn.classList.remove('hidden');

                } else if (formData.get('existing_logo_url') === '') {
                     // --- Reset sidebar on save (if logo was removed) ---
                    const sidebarImage = document.getElementById('sidebar-logo-image');
                    const sidebarText = document.getElementById('sidebar-logo-text');
                    if (sidebarImage && sidebarText) {
                        sidebarImage.src = '';
                        sidebarImage.classList.add('hidden');
                        sidebarText.classList.remove('hidden');
                    }
                    if (removeLogoBtn) removeLogoBtn.classList.add('hidden');
                }

                saveCompanyBtn.innerHTML = 'Saved!';
                saveCompanyBtn.classList.add('bg-green-600', 'hover:bg-green-700');
                saveCompanyBtn.classList.remove('bg-red-600', 'hover:bg-red-700');
                setTimeout(() => {
                    saveCompanyBtn.innerHTML = 'Save Company Settings';
                    saveCompanyBtn.classList.remove('bg-green-600', 'hover:bg-green-700');
                    saveCompanyBtn.classList.add('bg-red-600', 'hover:bg-red-700');
                }, 2000);

            } else {
                throw new Error(result.message);
            }
        } catch (e) {
            alert('Error saving settings: ' + e.message);
        } finally {
            saveCompanyBtn.disabled = false;
            if (!saveCompanyBtn.classList.contains('bg-green-600')) {
                saveCompanyBtn.innerHTML = 'Save Company Settings';
            }
        }
    });
}
    
    // Initial load (only if the form exists on the page)
    if (companyForm) {
        loadCompanySettings();
    }


    // --- User Roles & Permissions Functionality (Mock Data) ---
    const userListTbody = document.getElementById('user-list-tbody');
    let activeUserId = null;
    let users = {
        'user1': { name: 'Abdullah Al-Qahtani', email: 'admin@reva.com', status: 'Confirmed', permissions: { billing_access: 'manager', 'perm-apply-discounts': true, customer_access: 'user', meter_access: 'user', analytics_access: 'viewer', dashboard_access: 'viewer', admin_access: 'admin' }},
        'user2': { name: 'Fatima Al-Mutairi', email: 'finance@reva.com', status: 'Confirmed', permissions: { billing_access: 'user', 'perm-apply-discounts': true, customer_access: 'viewer', meter_access: 'viewer', analytics_access: 'viewer', dashboard_access: 'viewer', admin_access: 'none' }},
        'user3': { name: 'Omar Al-Harbi', email: 'operator@reva.com', status: 'Pending', permissions: { billing_access: 'viewer', 'perm-apply-discounts': false, customer_access: 'user', meter_access: 'user', analytics_access: 'none', dashboard_access: 'viewer', admin_access: 'none' }}
    };

    const renderUserList = () => {
        if (!userListTbody) return;
        userListTbody.innerHTML = '';
        for (const userId in users) {
            const user = users[userId];
            const userRow = document.createElement('tr');
            // MODIFIED: Removed 'cursor-pointer'
            userRow.className = 'user-list-item hover:bg-slate-50 dark:hover:bg-gray-700';
            userRow.dataset.userId = userId;

            let statusBadge = '';
            if (user.status === 'Confirmed') {
                statusBadge = `<span class="px-3 py-1 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300">Confirmed</span>`;
            } else {
                statusBadge = `<span class="px-3 py-1 inline-flex text-xs leading-5 font-semibold rounded-full bg-yellow-100 text-yellow-800 dark:bg-yellow-900/50 dark:text-yellow-300">Pending</span>`;
            }

            userRow.innerHTML = `
                <td class="px-6 py-4 whitespace-nowrap">
                    <div class="flex items-center">
                     <div class="flex-shrink-0 h-10 w-10">
                            <img class="h-10 w-10 rounded-full" src="https://placehold.co/40x40/e2e8f0/475569?text=${user.name.charAt(0)}" alt="">
                        </div>
                     <div class="ml-4">
                            <div class="text-sm font-medium text-slate-900 dark:text-white">${user.name}</div>
                        </div>
                     </div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-slate-500 dark:text-slate-400">${user.email}</td>
                <td class="px-6 py-4 whitespace-nowrap">${statusBadge}</td>
                
                <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <button type="button" class="edit-user-btn text-red-600 hover:text-red-800 dark:text-red-500 dark:hover:text-red-400 font-semibold">Edit User</button>
                </td>
            `;
            userListTbody.appendChild(userRow);
        }
    };
    
    const createPermissionsFormHTML = (user) => {
        const p = user.permissions;
        const isChecked = (group, value) => p[group] === value ? 'checked' : '';
        const isCheckedBox = (perm) => p[perm] ? 'checked' : '';

        return `
            <div id="permissions-form-modal" class="space-y-6 h-[60vh] overflow-y-auto pr-2">
                <div class="bg-slate-50 dark:bg-gray-900/50 p-4 rounded-lg border border-slate-200 dark:border-gray-700">
                    <h4 class="font-semibold text-slate-800 dark:text-slate-200 mb-3">Account Actions</h4>
                     <div class="space-y-3">
                        <div>
                            <label for="new-password" class="block text-sm font-medium text-slate-700 dark:text-slate-300">Set New Password</label>
                            <input type="password" id="new-password" placeholder="••••••••" class="mt-1 block w-full rounded-md border-slate-300 dark:border-gray-600 bg-white dark:bg-gray-700 sm:text-sm">
                        </div>
                     <button id="deactivate-user-btn" class="w-full bg-yellow-500 text-white font-semibold py-2 px-4 rounded-lg hover:bg-yellow-600 text-sm">Deactivate User</button>
                        <div class="text-center pt-2">
                             <button type="button" id="delete-user-btn" class="text-sm font-medium text-red-600 hover:underline">Delete User Permanently</button>
                        </div>
                    </div>
                </div>
        
                <hr class="border-slate-200 dark:border-gray-700">
                <div>
                    <h4 class="font-semibold text-slate-800 dark:text-slate-200 mb-2">Billing & Invoicing</h4>
                    <div class="space-y-2"><label class="flex items-center"><input type="radio" name="billing_access" value="none" ${isChecked('billing_access', 'none')} class="h-4 w-4 text-red-600 border-gray-300 focus:ring-red-500"><span class="ml-2 text-sm">No Access</span></label><label class="flex items-center"><input type="radio" name="billing_access" value="viewer" ${isChecked('billing_access', 'viewer')} class="h-4 w-4 text-red-600 border-gray-300 focus:ring-red-500"><span class="ml-2 text-sm">View Only</span></label><label class="flex items-center"><input type="radio" name="billing_access" value="user" ${isChecked('billing_access', 'user')} class="h-4 w-4 text-red-600 border-gray-300 focus:ring-red-500"><span class="ml-2 text-sm">User</span></label><label class="flex items-center"><input type="radio" name="billing_access" value="manager" ${isChecked('billing_access', 'manager')} class="h-4 w-4 text-red-600 border-gray-300 focus:ring-red-500"><span class="ml-2 text-sm">Manager</span></label></div>
                    <div class="pl-6 mt-3 border-l-2 border-slate-200 dark:border-gray-700"><label class="flex items-center"><input type="checkbox" id="perm-apply-discounts" ${isCheckedBox('perm-apply-discounts')} class="h-4 w-4 rounded border-gray-300 text-red-600 focus:ring-red-500"><span class="ml-2 text-sm">Allow Discounts</span></label></div>
                </div>
                <div>
                     <h4 class="font-semibold text-slate-800 dark:text-slate-200 mb-2">Customer Management</h4>
                    <div class="space-y-2"><label class="flex items-center"><input type="radio" name="customer_access" value="none" ${isChecked('customer_access', 'none')} class="h-4 w-4 text-red-600 border-gray-300 focus:ring-red-500"><span class="ml-2 text-sm">No Access</span></label><label class="flex items-center"><input type="radio" name="customer_access" value="viewer" ${isChecked('customer_access', 'viewer')} class="h-4 w-4 text-red-600 border-gray-300 focus:ring-red-500"><span class="ml-2 text-sm">View Only</span></label><label class="flex items-center"><input type="radio" name="customer_access" value="user" ${isChecked('customer_access', 'user')} class="h-4 w-4 text-red-600 border-gray-300 focus:ring-red-500"><span class="ml-2 text-sm">Create & Edit</span></label></div>
                </div>
        
                <div>
                     <h4 class="font-semibold text-slate-800 dark:text-slate-200 mb-2">Meter Operations</h4>
                    <div class="space-y-2"><label class="flex items-center"><input type="radio" name="meter_access" value="none" ${isChecked('meter_access', 'none')} class="h-4 w-4 text-red-600 border-gray-300 focus:ring-red-500"><span class="ml-2 text-sm">No Access</span></label><label class="flex items-center"><input type="radio" name="meter_access" value="viewer" ${isChecked('meter_access', 'viewer')} class="h-4 w-4 text-red-600 border-gray-300 focus:ring-red-500"><span class="ml-2 text-sm">View Only</span></label><label class="flex items-center"><input type="radio" name="meter_access" value="user" ${isChecked('meter_access', 'user')} class="h-4 w-4 text-red-600 border-gray-300 focus:ring-red-500"><span class="ml-2 text-sm">Operator</span></label></div>
                 </div>
                <div>
                     <h4 class="font-semibold text-slate-800 dark:text-slate-200 mb-2">Analytics & Reports</h4>
                     <div class="space-y-2"><label class="flex items-center"><input type="radio" name="analytics_access" value="none" ${isChecked('analytics_access', 'none')} class="h-4 w-4 text-red-600 border-gray-300 focus:ring-red-500"><span class="ml-2 text-sm">No Access</span></label><label class="flex items-center"><input type="radio" name="analytics_access" value="viewer" ${isChecked('analytics_access', 'viewer')} class="h-4 w-4 text-red-600 border-gray-300 focus:ring-red-500"><span class="ml-2 text-sm">View Access</span></label></div>
                </div>
         
                <div>
                     <h4 class="font-semibold text-slate-800 dark:text-slate-200 mb-2">Dashboard</h4>
                     <div class="space-y-2"><label class="flex items-center"><input type="radio" name="dashboard_access" value="none" ${isChecked('dashboard_access', 'none')} class="h-4 w-4 text-red-600 border-gray-300 focus:ring-red-500"><span class="ml-2 text-sm">No Access</span></label><label class="flex items-center"><input type="radio" name="dashboard_access" value="viewer" ${isChecked('dashboard_access', 'viewer')} class="h-4 w-4 text-red-600 border-gray-300 focus:ring-red-500"><span class="ml-2 text-sm">View Access</span></label></div>
                </div>
                <div>
                    <h4 class="font-semibold text-slate-800 dark:text-slate-200 mb-2">Administration</h4>
                     <div class="space-y-2"><label class="flex items-center"><input type="radio" name="admin_access" value="none" ${isChecked('admin_access', 'none')} class="h-4 w-4 text-red-600 border-gray-300 focus:ring-red-500"><span class="ml-2 text-sm">No Access</span></label><label class="flex items-center"><input type="radio" name="admin_access" value="admin" ${isChecked('admin_access', 'admin')} class="h-4 w-4 text-red-600 border-gray-300 focus:ring-red-500"><span class="ml-2 text-sm">Administrator</span></label></div>
                </div>
            </div>
        `;
    };

    if (userListTbody) {
        userListTbody.addEventListener('click', (e) => {
            // MODIFIED: Look for a click on the button, not the row
            const editButton = e.target.closest('.edit-user-btn');

            // If the click was not on an edit button, do nothing
            if (!editButton) {
                return;
            }

            // MODIFIED: Find the parent row *of the button*
            const userRow = editButton.closest('.user-list-item');
            
            if (userRow) {
                const userId = userRow.dataset.userId;
                activeUserId = userId;
                
                const user = users[userId];
                const formHTML = createPermissionsFormHTML(user);
                
                openModal(`Editing: ${user.name}`, formHTML, 'Save Permissions', () => {
                 
                    const newPermissions = {};
                    const formInModal = document.getElementById('permissions-form-modal');
                    const newPassword = formInModal.querySelector('#new-password').value;
                     if(newPassword) {
                         alert(`Password changed for ${user.name}.`);
                    }
                    
                     formInModal.querySelectorAll('input[type="radio"]:checked, input[type="checkbox"]').forEach(input => {
                           if (input.type === 'radio') {
                             newPermissions[input.name] = input.value;
                            } else {
                              newPermissions[input.id] = input.checked;
                            }
                    });
                    users[activeUserId].permissions = newPermissions;
                    alert(`${user.name}'s permissions have been updated.`);
                    closeModal();
                }, 'lg');

                const deactivateBtn = document.getElementById('deactivate-user-btn');
                if (deactivateBtn) {
                    deactivateBtn.addEventListener('click', () => {
                         if (confirm(`Are you sure you want to deactivate ${user.name}?`)) {
                            alert(`${user.name} has been deactivated.`);
                            closeModal();
                        }
                    });
                }

                const deleteBtn = document.getElementById('delete-user-btn');
                if(deleteBtn) {
                    deleteBtn.addEventListener('click', () => {
                        if (confirm(`Are you sure you want to permanently delete ${user.name}? This action cannot be undone.`)) {
                            delete users[userId];
                            renderUserList();
                            alert(`${user.name} has been deleted.`);
                            closeModal();
                        }
                    });
                }
            }
        });
    }

    const addUserBtn = document.getElementById('add-user-btn');
    if (addUserBtn) {
        addUserBtn.addEventListener('click', () => {
            const content = `
                <div class="space-y-4">
                    <div>
                        <label for="new-user-name" class="block text-sm font-medium text-slate-700 dark:text-slate-300">Full Name</label>
                        <input type="text" id="new-user-name" class="mt-1 block w-full rounded-md border-slate-300 dark:border-gray-600 bg-white dark:bg-gray-700" required>
                    </div>
                    <div>
                        <label for="new-user-email" class="block text-sm font-medium text-slate-700 dark:text-slate-300">Email</label>
                        <input type="email" id="new-user-email" class="mt-1 block w-full rounded-md border-slate-300 dark:border-gray-600 bg-white dark:bg-gray-700" required>
                    </div>
                 <div class="pt-2">
                        <label class="flex items-center">
                            <input type="checkbox" id="send-invitation" class="h-4 w-4 rounded border-gray-300 text-red-600 focus:ring-red-500" checked>
                            <span class="ml-2 text-sm text-slate-600 dark:text-slate-300">Send invitation email</span>
                        </label>
                    </div>
                </div>`;
            openModal('Add New User', content, 'Add User', () => {
                const name = document.getElementById('new-user-name').value;
                const email = document.getElementById('new-user-email').value;
                const sendInvitation = document.getElementById('send-invitation').checked;
                if (name && email) {
                    const newId = 'user' + (Object.keys(users).length + 1);
                    users[newId] = {
                        name, email, status: 'Pending',
                        permissions: { billing_access: 'none', 'perm-apply-discounts': false, customer_access: 'none', meter_access: 'none', analytics_access: 'none', dashboard_access: 'none', admin_access: 'none' }
                    };
                    renderUserList();
                 
                    if (sendInvitation) {
                        alert(`User ${name} added and invitation sent to ${email}.`);
                    } else {
                        alert(`User ${name} added.`);
                    }
                    closeModal();
                }
            });
        });
    }

    // Only render the user list if the element exists
    if(userListTbody) {
        renderUserList();
    }
});