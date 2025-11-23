document.addEventListener('DOMContentLoaded', () => {

    // --- CACHE DOM ELEMENTS ---
    const yearSelect = document.getElementById('dash-year-select');
    
    const customerDropdownContainer = document.getElementById('customer-dropdown-container');
    const customerSelectHidden = document.getElementById('dash-customer-select'); // The hidden input
    const customerSearchInput = document.getElementById('dash-customer-search');  // The visible search bar
    const customerToggleButton = document.getElementById('dash-customer-toggle');   // The dropdown arrow
    const customerList = document.getElementById('dash-customer-list');       // The list container
    
    let allCustomers = [];

    const kpiRevenue = document.getElementById('kpi-total-revenue');
    const kpiConsumption = document.getElementById('kpi-total-consumption');
    const kpiBills = document.getElementById('kpi-total-bills');
    const kpiAvgBill = document.getElementById('kpi-avg-bill');

    const revenueCanvas = document.getElementById('revenueChart');
    const consumptionCanvas = document.getElementById('consumptionChart');

    let revenueChartInstance = null;
    let consumptionChartInstance = null;

    const MONTH_LABELS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    
    // --- 1. LOAD INITIAL FILTERS (YEARS) ---
    async function loadYears() {
        try {
            const response = await fetch('/api/dashboard/years');
            const data = await response.json();

            if (data.status === 'success' && data.years.length > 0) {
                yearSelect.innerHTML = '<option value="">Select a year</option>'; // Placeholder
                data.years.forEach(year => {
                    const option = new Option(year, year);
                    yearSelect.add(option);
                });
            } else {
                yearSelect.innerHTML = '<option value="">No data found</option>';
            }
        } catch (e) {
            console.error(e);
            yearSelect.innerHTML = '<option value="">Error loading years</option>';
        }
    }

    // --- 2. LOAD CUSTOMERS WHEN YEAR CHANGES ---
    async function loadCustomers() {
        const year = yearSelect.value;
        
        // Reset customer input
        customerSearchInput.value = '';
        customerSelectHidden.value = '';

        if (!year) {
            // If "Select a year" is chosen
            customerSearchInput.placeholder = 'Select a year first';
            customerSearchInput.disabled = true;
            customerToggleButton.disabled = true;
            resetDashboard(); // Clear the dashboard
            return; // Stop here
        }
        
        customerSearchInput.placeholder = 'Loading customers...';
        customerSearchInput.disabled = true;
        customerToggleButton.disabled = true;

        try {
            // Fetch customers for the selected year
            const url = `/api/dashboard/customers?year=${year}`;
            const response = await fetch(url);
            const data = await response.json();

            if (data.status === 'success') {
                allCustomers = ['All Customers', ...data.customers]; // Store the full list
                buildCustomerList(allCustomers); // Build the dropdown
                
                customerSearchInput.placeholder = 'Search customers...';
                
                // Set default to "All Customers"
                customerSelectHidden.value = 'All Customers'; 
                customerSearchInput.value = 'All Customers';

                customerSearchInput.disabled = false;
                customerToggleButton.disabled = false;
            } else {
                customerSearchInput.placeholder = 'No customers found';
            }
        } catch (e) {
            console.error(e);
            customerSearchInput.placeholder = 'Error loading customers';
        }
    }

    // --- 3. FETCH & DISPLAY DASHBOARD DATA ---
    async function fetchDashboardData() {
        const year = yearSelect.value;
        const customer = customerSelectHidden.value;
        
        // Don't fetch if no year or customer is selected
        if (!year || !customer) {
            resetDashboard();
            return;
        }
        
        // Show loading state IN THE CHARTS
        kpiRevenue.textContent = 'Loading...';
        kpiConsumption.textContent = 'Loading...';
        kpiBills.textContent = 'Loading...';
        kpiAvgBill.textContent = 'Loading...';

        try {
            // Build query URL
            let url = `/api/dashboard/data?year=${year}&customer=${encodeURIComponent(customer)}`;

            const response = await fetch(url);
            const data = await response.json();

            if (data.status !== 'success') {
                throw new Error(data.message || 'Failed to fetch data');
            }
            
            updateKPIs(data.kpis);
            updateCharts(data.chartData, data.viewType);

        } catch (e) {
            console.error(e);
            alert('An error occurred while fetching dashboard data.');
            resetDashboard(); // Reset to empty on error
        }
    }
    
    // --- 4. Reset Dashboard Function ---
    function resetDashboard() {
        if (revenueChartInstance) revenueChartInstance.destroy();
        if (consumptionChartInstance) consumptionChartInstance.destroy();
        
        kpiRevenue.textContent = 'SAR 0.00';
        kpiConsumption.textContent = '0.00 m³';
        kpiBills.textContent = '0';
        kpiAvgBill.textContent = 'SAR 0.00';
    }

    // --- 5. UPDATE KPI CARDS ---
    function updateKPIs(kpis) {
        kpiRevenue.textContent = `SAR ${kpis.total_revenue}`;
        kpiConsumption.textContent = `${kpis.total_consumption} m³`;
        kpiBills.textContent = kpis.total_bills;
        kpiAvgBill.textContent = `SAR ${kpis.avg_bill}`;
    }

    // --- 6. UPDATE CHARTS (Main logic) ---
    function updateCharts(chartData, viewType) {
        if (revenueChartInstance) revenueChartInstance.destroy();
        if (consumptionChartInstance) consumptionChartInstance.destroy();

        if (viewType === 'all') {
            createAllCustomersCharts(chartData);
        } else {
            createSpecificCustomerCharts(chartData);
        }
    }

    // --- 7. SCENARIO 1: "All Customers" Chart ---
    function createAllCustomersCharts(data) {
        const revenueData = data.map(m => m.revenue);
        const consumptionData = data.map(m => m.consumption);
        const chartTextColor = document.body.classList.contains('dark') ? '#9ca3af' : '#6b7280';

        revenueChartInstance = new Chart(revenueCanvas, {
            type: 'bar',
            data: {
                labels: MONTH_LABELS,
                datasets: [{
                    label: 'Total Revenue',
                    data: revenueData,
                    // --- 💡 FIX: Changed from RED to GREEN ---
                    backgroundColor: 'rgba(34, 197, 94, 0.6)', // <-- GREEN
                    borderColor: 'rgba(34, 197, 94, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { 
                        beginAtZero: true, 
                        ticks: { color: chartTextColor },
                        grid: { color: document.body.classList.contains('dark') ? '#4b5563' : '#e5e7eb' }
                    },
                    x: { 
                        ticks: { color: chartTextColor },
                        grid: { display: false }
                    }
                },
                plugins: { legend: { labels: { color: chartTextColor } } }
            }
        });
        
        consumptionChartInstance = new Chart(consumptionCanvas, {
            type: 'bar',
            data: {
                labels: MONTH_LABELS,
                datasets: [{
                    label: 'Total Consumption',
                    data: consumptionData,
                    backgroundColor: 'rgba(59, 130, 246, 0.6)', // <-- BLUE
                    borderColor: 'rgba(59, 130, 246, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { 
                        beginAtZero: true, 
                        ticks: { color: chartTextColor },
                        grid: { color: document.body.classList.contains('dark') ? '#4b5563' : '#e5e7eb' }
                    },
                    x: { 
                        ticks: { color: chartTextColor },
                        grid: { display: false }
                    }
                },
                plugins: { legend: { labels: { color: chartTextColor } } }
            }
        });
    }

    // --- 8. SCENARIO 2: "Specific Customer" Grouped Chart ---
    function createSpecificCustomerCharts(data) {
        const chartTextColor = document.body.classList.contains('dark') ? '#9ca3af' : '#6b7280';
        
        const allDevices = new Set();
        data.forEach(month => {
            month.devices.forEach(device => {
                allDevices.add(device.serial);
            });
        });
        const devices = Array.from(allDevices); 
        
        const revenueDatasets = devices.map((serial, index) => {
            // --- Generate shades of GREEN for Revenue ---
            const hue = 130 + (index * 25); // Start at green (130) and vary
            const color = `hsl(${hue}, 60%, 45%)`; 
            return {
                label: serial,
                data: data.map(month => {
                    return month.devices
                        .filter(d => d.serial === serial)
                        .reduce((sum, d) => sum + d.revenue, 0);
                }),
                backgroundColor: color.replace(')', ', 0.6)'), 
                borderColor: color,
                borderWidth: 1
            };
        });

        const consumptionDatasets = devices.map((serial, index) => {
            // --- Generate shades of BLUE for Consumption ---
            const hue = 220 + (index * 25); // Start at blue (220) and vary
            const color = `hsl(${hue}, 70%, 55%)`;
            return {
                label: serial,
                data: data.map(month => {
                    return month.devices
                        .filter(d => d.serial === serial)
                        .reduce((sum, d) => sum + d.consumption, 0);
                }),
                backgroundColor: color.replace(')', ', 0.6)'),
                borderColor: color,
                borderWidth: 1
            };
        });

        revenueChartInstance = new Chart(revenueCanvas, {
            type: 'bar',
            data: {
                labels: MONTH_LABELS,
                datasets: revenueDatasets
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { 
                        beginAtZero: true, 
                        stacked: true, 
                        ticks: { color: chartTextColor },
                        grid: { color: document.body.classList.contains('dark') ? '#4b5563' : '#e5e7eb' }
                    },
                    x: { 
                        ticks: { color: chartTextColor },
                        grid: { display: false }
                    }
                },
                plugins: {
                    legend: { position: 'top', labels: { color: chartTextColor } },
                    tooltip: {
                        callbacks: {
                            title: (tooltipItems) => `Month: ${tooltipItems[0].label}`,
                            label: (tooltipItem) => `Device: ${tooltipItem.dataset.label}`,
                            afterLabel: (tooltipItem) => `Revenue: SAR ${tooltipItem.raw.toFixed(2)}`
                        }
                    }
                }
            }
        });

        consumptionChartInstance = new Chart(consumptionCanvas, {
            type: 'bar',
            data: {
                labels: MONTH_LABELS,
                datasets: consumptionDatasets
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { 
                        beginAtZero: true, 
                        stacked: true, 
                        ticks: { color: chartTextColor },
                        grid: { color: document.body.classList.contains('dark') ? '#4b5563' : '#e5e7eb' }
                    },
                    x: { 
                        ticks: { color: chartTextColor },
                        grid: { display: false }
                    }
                },
                plugins: {
                    legend: { position: 'top', labels: { color: chartTextColor } },
                    tooltip: {
                        callbacks: {
                            title: (tooltipItems) => `Month: ${tooltipItems[0].label}`,
                             label: (tooltipItem) => `Device: ${tooltipItem.dataset.label}`,
                            afterLabel: (tooltipItem) => `Consumption: ${tooltipItem.raw.toFixed(2)} m³`
                        }
                    }
                }
            }
        });
    }

    // --- 9. SEARCHABLE DROPDOWN LOGIC ---
    function buildCustomerList(customers) {
        customerList.innerHTML = ''; // Clear old list
        customers.forEach(customer => {
            const item = document.createElement('div');
            item.textContent = customer;
            item.dataset.value = customer;
            item.className = 'px-4 py-2 text-sm text-slate-700 dark:text-slate-200 hover:bg-red-100 dark:hover:bg-red-900 cursor-pointer';
            
            item.addEventListener('click', () => {
                customerSearchInput.value = customer;    
                customerSelectHidden.value = customer; 
                customerList.classList.add('hidden');  
                fetchDashboardData(); // <-- AUTO-LOAD DATA on click
            });
            customerList.appendChild(item);
        });
    }

    customerToggleButton.addEventListener('click', () => {
        customerList.classList.toggle('hidden');
    });

    customerSearchInput.addEventListener('input', () => {
        const searchTerm = customerSearchInput.value.toLowerCase();
        const filteredCustomers = allCustomers.filter(c => c.toLowerCase().includes(searchTerm));
        buildCustomerList(filteredCustomers);
        customerList.classList.remove('hidden'); 
    });
    
    //
    // === 💡 MODIFICATION HERE ===
    // This listener now shows the FULL list on click, instead of filtering.
    //
    customerSearchInput.addEventListener('focus', () => {
        customerSearchInput.select(); 
        
        // OLD CODE (removed):
        // const searchTerm = customerSearchInput.value.toLowerCase();
        // const filteredCustomers = allCustomers.filter(c => c.toLowerCase().includes(searchTerm));
        // buildCustomerList(filteredCustomers);
        
        // NEW CODE:
        buildCustomerList(allCustomers); // Always show the full list on focus
        
        customerList.classList.remove('hidden');
    });
    // === END MODIFICATION ===
    //

    document.addEventListener('click', (e) => {
        if (!customerDropdownContainer.contains(e.target)) {
            customerList.classList.add('hidden');
        }
    });

    // --- 10. EVENT LISTENERS & INITIALIZE ---
    yearSelect.addEventListener('change', () => {
        loadCustomers();
        // We DO NOT fetch data here. We wait for the user to select a customer.
        // We just reset the dashboard.
        resetDashboard();
    });

    // --- INITIALIZE ---
    async function initializeDashboard() {
        await loadYears();
        
        // --- THIS IS THE FIX ---
        // 1. Get current year
        const currentYear = new Date().getFullYear().toString();
        
        // 2. Check if this year exists in the dropdown options
        const yearOption = Array.from(yearSelect.options).find(opt => opt.value === currentYear);
        
        if (yearOption) {
            // 3. If it exists, select it
            yearSelect.value = currentYear;
        } else {
            // 4. If not (e.g. no data for 2025), select the most recent year
            // (The first option is "Select a year", so we take the second)
            if (yearSelect.options.length > 1) {
                yearSelect.value = yearSelect.options[1].value;
            }
        }
        
        // 5. Load customers for the selected year
        await loadCustomers(); 
        
        // 6. Set customer to "All Customers" (this is already done inside loadCustomers)
        // We'll set it here again just to be 100% sure
        customerSelectHidden.value = 'All Customers';
        customerSearchInput.value = 'All Customers';

        // 7. Fetch the data for Current Year + All Customers
        fetchDashboardData();  
    }
    
    initializeDashboard();
});