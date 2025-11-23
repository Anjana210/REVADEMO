const express = require('express');
const router = express.Router(); // Use Express's Router
const { Pool } = require('pg');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const fastcsv = require('fast-csv');
const archiver = require('archiver');
const format = require('pg-format');
const ejs = require('ejs');
const puppeteer = require('puppeteer');
// FIX: Corrected import for p-limit to access the default export
const pLimit = require('p-limit').default; 

// In-memory progress tracker for bulk ZIP jobs
const bulkProgress = new Map();

// Import our shared middleware
const { requireStaff, requireWrite } = require('./middleware.js');

// Configure Multer for in-memory file storage
const storage = multer.memoryStorage();
// NOTE: Multer field name changed to 'consumption_file' to match the frontend
const upload = multer({ storage: storage }); 

// Contact email for capacity/license inquiries
const CONTACT_EMAIL = process.env.CONTACT_EMAIL || 'reva.zone@revartix.com';

// --- Database Connection Pool ---
const pool = new Pool(); // It will automatically use the .env variables
console.log('REVA LITEBILL: Database pool initialized.');

// --- LiteBill Config (from config.py) ---
const LITEBILL_CONFIG = {
    MAX_ROWS: 500, // Default limit, overridden by owner_info
    REQUIRED_REF_COLS: [
        'device.serialNo', 
        'Customer Name'
    ],
    REQUIRED_BILLING_COLS: [
        'device.serialNo', 
        'values.timestamp', 
        'values.volume.main (m3)', 
        'Customer #', 
        'Building #', 
        'Apartment #', 
        'Bill Duration Start Date', 
        'Bill Duration End Date', 
        'Net Consumption (m3)', 
        'Invoice Date'
    ]
};

// --- Helper function to parse dates ---
function parseCsvDate(dateStr) {
    if (!dateStr) return null;
    const parts = dateStr.split(/[\s/:]+/); 
    try {
        if (parts.length >= 5) {
            return new Date(parts[2], parts[1] - 1, parts[0], parts[3], parts[4]);
        } else if (parts.length === 3) {
            return new Date(parts[2], parts[1] - 1, parts[0]);
        }
        return null;
    } catch (e) {
        return null;
    }
}

// --- Helper to get owner license info ---
async function getOwnerInfo(ownerId) {
    const query = "SELECT max_rows_allowed, owner_name FROM owner_info WHERE id = $1 AND is_active = TRUE;";
    const { rows } = await pool.query(query, [ownerId]);
    return rows[0] || null;
}

// --- Helper to get existing reference data count for a given owner ---
async function getReferenceDataCount(ownerId) {
    const query = "SELECT COUNT(*) FROM reference_data WHERE owner_id = $1;";
    const { rows } = await pool.query(query, [ownerId]);
    return parseInt(rows[0].count, 10);
}

// --- Helper to get company settings (especially logo URL) ---
async function getCompanySettings() {
    // NOTE: This assumes company_settings has a single row with id = 1
    const query = "SELECT logo_url FROM company_settings WHERE id = 1;"; 
    const { rows } = await pool.query(query);
    return rows[0] || null;
}


//=======================================================================================//
// --- NEW STEP 1: UPLOAD REFERENCE DATA (Meter ID & Customer Name) ---
//=======================================================================================//
router.post('/api/upload-reference-data', requireWrite, upload.single('csv_file'), async (req, res) => {
    
    // NOTE: For simplicity, hardcode ownerId = 1. In a real app, this comes from req.user
    const ownerId = 1; 

    if (!req.file) {
        return res.status(400).json({ status: 'error', message: 'No file part in the request' });
    }

    let ownerInfo;
    try {
        ownerInfo = await getOwnerInfo(ownerId);
        if (!ownerInfo) {
            return res.status(403).json({ status: 'error', message: 'License check failed: Owner not found or inactive.' });
        }
    } catch (e) {
        console.error('Owner info lookup error:', e);
        return res.status(500).json({ status: 'error', message: 'Server error during license check.' });
    }

    const rows = [];
    const fileBuffer = req.file.buffer.toString('utf-8');

    // 1. Read and Validate CSV
    try {
        await new Promise((resolve, reject) => {
            const stream = fastcsv.parse({ headers: true })
                .on('error', (error) => reject(error))
                .on('data', (row) => rows.push(row))
                .on('end', (rowCount) => resolve(rowCount));
            
            stream.write(fileBuffer);
            stream.end();
        });

        if (rows.length === 0) {
            return res.status(400).json({ status: 'error', message: 'CSV file is empty.' });
        }

        const currentCount = await getReferenceDataCount(ownerId);
        const newTotalCount = currentCount + rows.length;

        // 2. Enforce License Limit
        if (newTotalCount > ownerInfo.max_rows_allowed) {
            const msg = `License Limit exceeded. Your current limit is ${ownerInfo.max_rows_allowed} meter IDs. Contact ${CONTACT_EMAIL} to increase capacity.`;
            return res.status(403).json({ status: 'error', message: msg, code: 'LICENSE_LIMIT_EXCEEDED' });
        }

        const headers = Object.keys(rows[0]);
        const missing = LITEBILL_CONFIG.REQUIRED_REF_COLS.filter(col => !headers.includes(col));
        
        if (missing.length > 0) {
            const msg = `CSV is missing required columns: ${missing.join(', ')}`;
            return res.status(400).json({ status: 'error', message: msg });
        }

        // 3. Database Upsert
        const data_to_insert = rows.map(row => [
            ownerId,
            row['device.serialNo'].trim(),
            row['Customer Name'].trim()
        ]);

        const client = await pool.connect();
        try {
            await client.query('BEGIN'); 
            
            let updatedCount = 0;
            let insertedCount = 0;
            
            // NOTE: Using raw loop for fine-grained control over UPSERT and timestamp setting
            for (const rowData of data_to_insert) {
                const [ owner_id, device_serialno, customer_name ] = rowData;
                
                // Attempt to update first (UPSERT logic)
                const updateQuery = `
                    UPDATE reference_data SET
                        customer_name = $3,
                        last_update_timestamp = TIMEZONE('Asia/Riyadh', NOW())
                    WHERE owner_id = $1 AND device_serialno = $2
                `;
                const updateResult = await client.query(updateQuery, [owner_id, device_serialno, customer_name]);
                
                if (updateResult.rowCount > 0) {
                    updatedCount++;
                } else {
                    // Insert new record if no update occurred
                    // NOTE: insert_timestamp is explicitly set here
                    const insertQuery = `
                        INSERT INTO reference_data (owner_id, device_serialno, customer_name, insert_timestamp) 
                        VALUES ($1, $2, $3, TIMEZONE('Asia/Riyadh', NOW()))
                    `;
                    await client.query(insertQuery, [owner_id, device_serialno, customer_name]);
                    insertedCount++;
                }
            }
            
            await client.query('COMMIT'); 
            
            const actionMsg = `Successfully updated ${updatedCount} existing and inserted ${insertedCount} new reference records. Total: ${newTotalCount} / ${ownerInfo.max_rows_allowed}.`;
            
            res.status(200).json({ status: 'success', message: actionMsg });

        } catch (dbError) {
            await client.query('ROLLBACK'); 
            console.error('Database upsert error:', dbError);
            res.status(500).json({ status: 'error', message: `Internal database error during insertion: ${dbError.message}` });
        } finally {
            client.release();
        }

    } catch (parseError) {
        console.error('Error reading or parsing CSV:', parseError);
        res.status(500).json({ status: 'error', message: `Error reading or parsing CSV: ${parseError.message}` });
    }
});


//=======================================================================================//
// --- NEW STEP 2: UPDATE REFERENCE DATA (Meter ID & Customer Name) ---
//=======================================================================================//

// 2A. API to fetch all reference data for the owner
router.get('/api/get-reference-data', requireStaff, async (req, res) => {
    const ownerId = 1; // Hardcoded ownerId
    try {
        // Fetching new timestamp columns
        const query = "SELECT device_serialno, customer_name, id, insert_timestamp, last_update_timestamp FROM reference_data WHERE owner_id = $1 ORDER BY id;";
        const { rows } = await pool.query(query, [ownerId]);
        res.json({ status: 'success', data: rows });
    } catch (e) {
        console.error('Error fetching reference data:', e);
        res.status(500).json({ status: 'error', message: 'Failed to fetch reference data.' });
    }
});


// 2B. API to update/delete reference data (Using the same URL structure as before, but pointing to reference_data)
router.post('/api/update-device-serial', requireWrite, async (req, res) => {
    const { changes } = req.body; // Array of { originalSerial, newSerial, newCustomerName }
    const ownerId = 1; 
    
    if (!changes || !Array.isArray(changes) || changes.length === 0) {
        return res.status(400).json({ status: 'error', message: 'No reference data changes provided.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        let updatedCount = 0;
        const changeResults = [];

        for (let i = 0; i < changes.length; i++) {
            const change = changes[i];
            const { originalSerial, newSerial, newCustomerName } = change;
            
            const result = {
                index: i,
                originalSerial,
                newSerial,
                newCustomerName,
                success: false,
                error: null
            };

            if (!originalSerial || !newSerial || !newCustomerName) {
                result.error = 'missing_fields';
                result.errorMessage = 'Missing required fields';
                changeResults.push(result);
                continue;
            }

            if (originalSerial === newSerial) {
                // Update Customer Name only
                const updateNameQuery = `
                    UPDATE reference_data 
                    SET customer_name = $1,
                        last_update_timestamp = TIMEZONE('Asia/Riyadh', NOW())
                    WHERE owner_id = $2 AND device_serialno = $3
                `;
                const updateNameResult = await client.query(updateNameQuery, [newCustomerName, ownerId, originalSerial]);
                if (updateNameResult.rowCount > 0) {
                    result.success = true;
                    updatedCount++;
                } else {
                    result.error = 'not_found';
                    result.errorMessage = `Meter ID ${originalSerial} not found for updating customer name.`;
                }
                changeResults.push(result);
                continue;
            }

            // Check if new serial already exists
            const conflictCheck = await client.query('SELECT id FROM reference_data WHERE owner_id = $1 AND device_serialno = $2 LIMIT 1', [ownerId, newSerial]);
            if (conflictCheck.rows.length > 0) {
                result.error = 'already_exists';
                result.errorMessage = `The New Meter ID (${newSerial}) already exists in the reference table.`;
                changeResults.push(result);
                continue;
            }

            // Update the device serial number and customer name
            const updateQuery = `
                UPDATE reference_data 
                SET device_serialno = $1, 
                    customer_name = $2,
                    last_update_timestamp = TIMEZONE('Asia/Riyadh', NOW())
                WHERE owner_id = $3 AND device_serialno = $4
            `;
            const updateResult = await client.query(updateQuery, [newSerial, newCustomerName, ownerId, originalSerial]);
            
            if (updateResult.rowCount > 0) {
                result.success = true;
                updatedCount++;
            } else {
                result.error = 'not_found';
                result.errorMessage = `Old Meter ID ${originalSerial} was not found in the reference table.`;
            }
            changeResults.push(result);
        }

        await client.query('COMMIT');

        res.status(200).json({
            status: updatedCount > 0 ? 'success' : 'partial',
            updated: updatedCount,
            changeResults: changeResults
        });

    } catch (dbError) {
        await client.query('ROLLBACK');
        console.error('Reference Data update error:', dbError);
        res.status(500).json({ 
            status: 'error', 
            message: 'Critical Error: Reference data updates failed due to a server issue. No changes were saved.',
            error: dbError.message 
        });
    } finally {
        client.release();
    }
});


//=======================================================================================//
// --- NEW STEP 3: UPLOAD BILLING DATA API (formerly Step 1) ---
//=======================================================================================//
// IMPORTANT: Multer field name is 'consumption_file' to match the frontend (reva_lite_bill.ejs)
router.post('/api/upload-billing-data', requireWrite, upload.single('consumption_file'), async (req, res) => {
    
    // Hardcoded ownerId
    const ownerId = 1;

    // --- 1. Validation & Parameter Retrieval ---
    if (!req.file) {
        // Log this error to help diagnose client-side failures
        console.log("DEBUG: Billing Upload Failed - req.file is null/undefined. Check file input name ('consumption_file') and form submission.");
        return res.status(400).json({ status: 'error', message: 'No file part in the request. Ensure the file input name is correct.' });
    }
    
    // --- DEBUG LOG: Check received file details ---
    console.log(`DEBUG: Billing file received. Filename: ${req.file.originalname}, Size: ${req.file.size} bytes.`);
    
    if (req.file.size === 0) {
        return res.status(400).json({ status: 'error', message: 'The uploaded CSV file is empty (0 bytes).', code: 'EMPTY_FILE' });
    }


    // --- Get data from FORM (New Step 4) ---
    const bill_month_year = req.body.bill_month; 
    const tariff_sar_str = req.body.tariff_sar;
    const vat_percent_str = req.body.vat_percent; 

    // Get "Other Charges" from form
    const form_charge_descs = Array.isArray(req.body.other_charge_desc) ? req.body.other_charge_desc : (req.body.other_charge_desc ? [req.body.other_charge_desc] : []);
    const form_charge_rates = Array.isArray(req.body.other_charge_rate) ? req.body.other_charge_rate : (req.body.other_charge_rate ? [req.body.other_charge_rate] : []);

    if (!bill_month_year || !tariff_sar_str || !vat_percent_str) {
        return res.status(400).json({ status: 'error', message: 'Missing bill_month, tariff_sar, or vat_percent.' });
    }

    let tariff, vat_percent;
    try {
        tariff = parseFloat(tariff_sar_str);
        vat_percent = parseFloat(vat_percent_str);
        if (tariff <= 0 || isNaN(tariff)) throw new Error("Tariff must be positive.");
        if (vat_percent < 0 || isNaN(vat_percent)) throw new Error("VAT must be a non-negative number.");
    } catch (e) {
        return res.status(400).json({ status: 'error', message: `Invalid tariff or VAT rate provided. ${e.message}` });
    }

    // NEW: Prepare "Other Charges" from the form to be saved
    const formCharges = [];
    let total_form_charges = 0;
    for (let i = 0; i < form_charge_descs.length; i++) {
        const desc = form_charge_descs[i];
        const rate = parseFloat(form_charge_rates[i]) || 0;
        if (desc && rate > 0) {
            formCharges.push({ desc: desc, rate: rate });
            total_form_charges += rate;
        }
    }

    // Assign form charges to the columns you want
    let c_charge_1_desc = null, c_charge_1_rate = 0;
    let c_charge_2_desc = null, c_charge_2_rate = 0;
    let c_charge_3_desc = null, c_charge_3_rate = 0;

    if (formCharges[0]) {
        c_charge_1_desc = formCharges[0].desc;
        c_charge_1_rate = formCharges[0].rate;
    }
    if (formCharges[1]) {
        c_charge_2_desc = formCharges[1].desc;
        c_charge_2_rate = formCharges[1].rate;
    }
    if (formCharges[2]) {
        c_charge_3_desc = formCharges[2].desc;
        c_charge_3_rate = formCharges[2].rate;
    }

    const rows = [];
    const fileBuffer = req.file.buffer.toString('utf-8');

    // --- 2. Read and Validate CSV ---
    try {
        await new Promise((resolve, reject) => {
            const stream = fastcsv.parse({ headers: true })
                .on('error', (error) => reject(error))
                .on('data', (row) => rows.push(row))
                .on('end', (rowCount) => resolve(rowCount));
            
            stream.write(fileBuffer);
            stream.end();
        });

        if (rows.length === 0) {
            return res.status(400).json({ status: 'error', message: 'CSV file is empty.' });
        }

        // NOTE: Max rows check moved to reference data upload (New Step 1)
        // Check for required billing columns (Customer Name is removed from required, as it comes from ref data)
        const headers = Object.keys(rows[0]);
        const missing = LITEBILL_CONFIG.REQUIRED_BILLING_COLS.filter(col => !headers.includes(col));
        
        if (missing.length > 0) {
            const msg = `CSV is missing required billing columns: ${missing.join(', ')}`;
            return res.status(400).json({ status: 'error', message: msg });
        }

        // --- 3. Data Preprocessing, Lookup, and Calculation ---
        const data_to_insert = [];
        
        // Fetch reference data for lookup
        const refDataQuery = "SELECT device_serialno, customer_name FROM reference_data WHERE owner_id = $1;";
        const refDataResult = await pool.query(refDataQuery, [ownerId]);
        const refDataMap = new Map(refDataResult.rows.map(row => [row.device_serialno, row.customer_name]));

        const missingRefIds = new Set();

        for (const row of rows) {
            const device_serialno = row['device.serialNo'];
            const customer_name = refDataMap.get(device_serialno);

            if (!customer_name) {
                missingRefIds.add(device_serialno);
                continue; // Skip processing this row if reference data is missing
            }
            
            const net_consumption_m3 = parseFloat(row['Net Consumption (m3)']);
            if (isNaN(net_consumption_m3)) {
                throw new Error(`Invalid Net Consumption for device ${device_serialno}`);
            }

            // --- Start Calculations ---
            const consumption_charge = tariff * net_consumption_m3;
            
            const subtotal = consumption_charge + total_form_charges;
            const vat_amount = subtotal * (vat_percent / 100);
            const total_bill_amount_sar = subtotal + vat_amount;
            // --- End Calculations ---

            // This array MUST match the order of the INSERT query below
            const formattedRow = [
                bill_month_year,
                tariff,
                device_serialno,
                parseCsvDate(row['values.timestamp']), 
                parseFloat(row['values.volume.main (m3)']), 
                customer_name, // Pulled from reference data
                row['Customer #'],
                row['Building #'],
                row['Apartment #'],
                parseCsvDate(row['Bill Duration Start Date']), 
                parseCsvDate(row['Bill Duration End Date']), 
                net_consumption_m3,
                parseCsvDate(row['Invoice Date']), 
                total_bill_amount_sar,
                vat_percent,     
                c_charge_1_desc, 
                c_charge_1_rate, 
                c_charge_2_desc, 
                c_charge_2_rate, 
                c_charge_3_desc, 
                c_charge_3_rate  
            ];

            if (!formattedRow[3] || !formattedRow[9] || isNaN(formattedRow[11]) || isNaN(formattedRow[13])) {
                 throw new Error(`Critical data conversion failed for device ${device_serialno}. Check dates and numbers.`);
            }

            data_to_insert.push(formattedRow);
        }
        
        if (missingRefIds.size > 0) {
            const missingList = Array.from(missingRefIds).slice(0, 5).join(', ');
            const errorMsg = `Processing failed: ${missingRefIds.size} device serial numbers in the CSV are missing corresponding Customer Name data in Step 1 reference table (e.g., ${missingList}${missingRefIds.size > 5 ? '...' : ''}). Please upload or update the reference data first.`;
            return res.status(400).json({ status: 'error', message: errorMsg, code: 'MISSING_REFERENCE_DATA' });
        }


        // --- 4. Database Insertion/Update into FINAL_BILLING_DATA (UPSERT) ---
        const client = await pool.connect();
        try {
            await client.query('BEGIN'); 
            
            let updatedCount = 0;
            let insertedCount = 0;
            
            // Process each row: UPDATE if exists (same month + device_serialno), else INSERT
            for (const rowData of data_to_insert) {
                const [
                    upload_month, upload_tariff_sar, device_serialno,
                    final_reading_timestamp, final_reading_volume_m3,
                    customer_name, customer_hash, building_hash,
                    apartment_hash, bill_start_date, bill_end_date,
                    net_consumption_m3, invoice_date_csv, total_bill_amount_sar,
                    vat_percent,
                    csv_charge_1_desc, csv_charge_1_rate,
                    csv_charge_2_desc, csv_charge_2_rate,
                    csv_charge_3_desc, csv_charge_3_rate
                ] = rowData;
                
                // Check if record exists for this month and device
                const checkQuery = `
                    SELECT id FROM final_billing_data 
                    WHERE upload_month = $1 AND device_serialno = $2
                    LIMIT 1
                `;
                const checkResult = await client.query(checkQuery, [upload_month, device_serialno]);
                
                if (checkResult.rows.length > 0) {
                    // UPDATE existing record
                    const updateQuery = `
                        UPDATE final_billing_data SET
                            upload_tariff_sar = $1,
                            final_reading_timestamp = $2,
                            final_reading_volume_m3 = $3,
                            customer_name = $4,
                            customer_hash = $5,
                            building_hash = $6,
                            apartment_hash = $7,
                            bill_start_date = $8,
                            bill_end_date = $9,
                            net_consumption_m3 = $10,
                            invoice_date_csv = $11,
                            total_bill_amount_sar = $12,
                            vat_percent = $13,
                            csv_charge_1_desc = $14,
                            csv_charge_1_rate = $15,
                            csv_charge_2_desc = $16,
                            csv_charge_2_rate = $17,
                            csv_charge_3_desc = $18,
                            csv_charge_3_rate = $19
                        WHERE upload_month = $20 AND device_serialno = $21
                    `;
                    await client.query(updateQuery, [
                        upload_tariff_sar, final_reading_timestamp, final_reading_volume_m3,
                        customer_name, customer_hash, building_hash, apartment_hash,
                        bill_start_date, bill_end_date, net_consumption_m3,
                        invoice_date_csv, total_bill_amount_sar, vat_percent,
                        csv_charge_1_desc, csv_charge_1_rate,
                        csv_charge_2_desc, csv_charge_2_rate,
                        csv_charge_3_desc, csv_charge_3_rate,
                        upload_month, device_serialno
                    ]);
                    updatedCount++;
                } else {
                    // INSERT new record
                    const insertQuery = `
                        INSERT INTO final_billing_data (
                            upload_month, upload_tariff_sar, device_serialno, 
                            final_reading_timestamp, final_reading_volume_m3, 
                            customer_name, customer_hash, building_hash, 
                            apartment_hash, bill_start_date, bill_end_date, 
                            net_consumption_m3, invoice_date_csv, total_bill_amount_sar,
                            vat_percent, 
                            csv_charge_1_desc, csv_charge_1_rate,
                            csv_charge_2_desc, csv_charge_2_rate,
                            csv_charge_3_desc, csv_charge_3_rate
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
                    `;
                    await client.query(insertQuery, rowData);
                    insertedCount++;
                }
            }
            
            await client.query('COMMIT'); 
            
            const actionMsg = updatedCount > 0 && insertedCount > 0 
                ? `Updated ${updatedCount} existing records and inserted ${insertedCount} new records.`
                : updatedCount > 0 
                    ? `Successfully updated ${updatedCount} existing records.`
                    : `Successfully inserted ${insertedCount} new records.`;
            
            res.status(200).json({ status: 'success', message: actionMsg });

        } catch (dbError) {
            await client.query('ROLLBACK'); 
            console.error('Database insertion/update error:', dbError);
            res.status(500).json({ status: 'error', message: `Internal database error during insertion/update: ${dbError.message}` });
        } finally {
            client.release();
        }

    } catch (parseError) {
        console.error('Error reading or parsing CSV:', parseError);
        res.status(500).json({ status: 'error', message: `Error reading or parsing CSV: ${parseError.message}` });
    }
});


//=======================================================================================//
// --- NEW STEP 5: DATA RETRIEVAL API (Required by JS for PDF generation) ---
//=======================================================================================//
router.post('/api/get-invoicing-data', requireStaff, async (req, res) => {
    const { target_month } = req.body;

    if (!target_month) {
        return res.status(400).json({ status: 'error', message: 'Missing target_month parameter.' });
    }

    try {
        const query = "SELECT * FROM final_billing_data WHERE upload_month = $1 ORDER BY id;";
        const { rows } = await pool.query(query, [target_month]);

        if (rows.length === 0) {
            return res.json({ status: 'info', message: `No final bill records found for ${target_month}.`, bill_data: [] });
        }

        res.json({
            status: 'success',
            message: `Retrieved data for ${rows.length} invoices.`,
            bill_data: rows
        });

    } catch (e) {
        console.error('Data retrieval error:', e);
        res.status(500).json({ status: 'error', message: `Internal data retrieval error: ${e.message}` });
    }
});

//=======================================================================================//
// --- NEW: API TO GET DISTINCT UPLOAD MONTHS (Step 5 requirement) ---
//=======================================================================================//
router.get('/api/get-available-months', requireStaff, async (req, res) => {
    try {
        const query = "SELECT DISTINCT upload_month FROM final_billing_data ORDER BY upload_month DESC;";
        const { rows } = await pool.query(query);
        
        const months = rows.map(row => row.upload_month); 

        res.json({
            status: 'success',
            months: months
        });

    } catch (e) {
        console.error('Error fetching available months:', e);
        res.status(500).json({ status: 'error', message: `Internal error: ${e.message}` });
    }
});


//=======================================================================================//
// --- PDF GENERATION AND DOWNLOAD APIs (Optimized for Bulk Speed) ---
//=======================================================================================//

function formatPDFDate(date_value) {
    if (!date_value) return '';
    try {
        const d = new Date(date_value);
        const day = String(d.getDate()).padStart(2, '0');
        const month = String(d.getMonth() + 1).padStart(2, '0');
        const year = d.getFullYear();
        return `${day}/${month}/${year}`;
    } catch (e) {
        return date_value; 
    }
}

async function generateInvoicePDFBuffer(bill_data, browserInstance = null) {
    
    // --- NEW: Fetch Company Settings ---
    let companySettings;
    try {
        companySettings = await getCompanySettings();
    } catch (e) {
        console.error('Error fetching company settings for PDF:', e);
        companySettings = { logo_url: null }; // Default safe fallback
    }
    let company_logo_url = companySettings ? companySettings.logo_url : null;
    // Ensure the logo renders in Puppeteer setContent by converting local paths to data URLs
    try {
        const toUnix = (p) => p.replace(/\\/g, '/');
        const tryResolve = (pLike) => {
            if (!pLike) return null;
            // If absolute and exists, use as-is
            if (path.isAbsolute(pLike) && fs.existsSync(pLike)) return pLike;
            const rel = pLike.replace(/^[\\/]+/, '');
            const candidates = [
                path.join(process.cwd(), rel),
                path.join(process.cwd(), 'Public', rel),
                path.resolve(__dirname, rel),
                path.resolve(__dirname, 'Public', rel),
                path.resolve(__dirname, '..', 'Public', rel)
            ];
            for (const c of candidates) {
                if (fs.existsSync(c)) return c;
            }
            return null;
        };

        // 1) Use DB value if present; else fallback to conventional uploads path
        let resolvedPath = tryResolve(company_logo_url);
        if (!resolvedPath) {
            resolvedPath = tryResolve(path.join('uploads', 'company-logo.png'));
        }

        // 2) If still not found but DB value is an http(s) URL, pass-through (no embed)
        if (!resolvedPath && company_logo_url && /^https?:\/\//i.test(company_logo_url)) {
            // Leave company_logo_url as remote URL
        } else if (resolvedPath) {
            // 3) Read and embed as data URL
            const fileBuf = fs.readFileSync(resolvedPath);
            const ext = path.extname(resolvedPath).toLowerCase();
            const mime = (
                ext === '.png' ? 'image/png' :
                (ext === '.jpg' || ext === '.jpeg') ? 'image/jpeg' :
                ext === '.webp' ? 'image/webp' :
                ext === '.svg' ? 'image/svg+xml' :
                'application/octet-stream'
            );
            company_logo_url = `data:${mime};base64,${fileBuf.toString('base64')}`;
            if (process.env.DEBUG_PDF === 'true') {
                console.log('PDF LOGO OK', { source: companySettings && companySettings.logo_url, resolvedPath, mime });
            }
        } else {
            // Final fallback: null (template shows text placeholder)
            company_logo_url = null;
            if (process.env.DEBUG_PDF === 'true') {
                console.warn('PDF LOGO MISSING', { source: companySettings && companySettings.logo_url });
            }
        }
    } catch (logoErr) {
        console.warn('Could not embed company logo for PDF:', logoErr && logoErr.message ? logoErr.message : logoErr);
        // Fallback: leave as-is (template will show fallback text if null)
    }
    // --- END NEW ---

    // --- 1. Original Calculations ---
    const consumption = parseFloat(bill_data.net_consumption_m3);
    const tariff = parseFloat(bill_data.upload_tariff_sar);
    const vat_percent = parseFloat(bill_data.vat_percent); // This is the value

    const consumption_charge = consumption * tariff;

    let total_other_charges = 0;
    const charges = []; // This is the original 'other charges' array

    if (bill_data.csv_charge_1_rate > 0) {
        const rate = parseFloat(bill_data.csv_charge_1_rate);
        charges.push({ desc: bill_data.csv_charge_1_desc, rate: rate }); // Store as number
        total_other_charges += rate;
    }
    if (bill_data.csv_charge_2_rate > 0) {
        const rate = parseFloat(bill_data.csv_charge_2_rate);
        charges.push({ desc: bill_data.csv_charge_2_desc, rate: rate }); // Store as number
        total_other_charges += rate;
    }
    if (bill_data.csv_charge_3_rate > 0) {
        const rate = parseFloat(bill_data.csv_charge_3_rate);
        charges.push({ desc: bill_data.csv_charge_3_desc, rate: rate }); // Store as number
        total_other_charges += rate;
    }

    const subtotal = consumption_charge + total_other_charges; // This is Total Before VAT
    const vat_amount = subtotal * (vat_percent / 100);       // This is Total VAT
    const total_bill = parseFloat(bill_data.total_bill_amount_sar); // This is Total After VAT

    // --- 2. FIX: Create ALL variables required by lite_invoice_template.ejs ---

    // A. inv_date and dueDateStr
    const inv_date_raw = bill_data.invoice_date_csv;
    // Use formatPDFDate (already defined in backend.js) for consistency
    const inv_date_formatted = formatPDFDate(inv_date_raw); 

    let dueDateStr = '-';
    if (inv_date_raw) {
        try {
            const invDate = new Date(inv_date_raw);
            invDate.setDate(invDate.getDate() + 20); // Add 20 days
            dueDateStr = formatPDFDate(invDate); // Use the existing helper
        } catch (e) {
            dueDateStr = '-'; 
        }
    }

    // B. billSummary (The template expects this to include consumption)
    const billSummary = [];
    
    // Add Water Consumption Value
    billSummary.push({
        description: 'Water Consumption Value',
        before_vat: consumption_charge, // number
        vat: consumption_charge * (vat_percent / 100), // number
        after_vat: consumption_charge * (1 + vat_percent / 100) // number
    });
    
    // Add "Other Charges" from the charges array
    charges.forEach(charge => {
        const rate = charge.rate; // This is already a number
        const charge_vat = rate * (vat_percent / 100);
        billSummary.push({
            description: charge.desc,
            before_vat: rate,
            vat: charge_vat,
            after_vat: rate + charge_vat
        });
    });

    // --- 3. Build the templateData object with the CORRECT names ---
    const templateData = {
        // Variables that worked
        bill: bill_data,
        company_logo_url: company_logo_url,
        consumption_m3: consumption.toFixed(2), // This one is fine as a string

        // --- FIXED/RENAMED variables to match EJS template ---
        
        // Dates
        inv_date: inv_date_formatted, // For: <%= inv_date %>
        dueDateStr: dueDateStr,       // For: <%= dueDateStr %>
        bill_start: formatPDFDate(bill_data.bill_start_date), // For: <%= bill_start %>
        bill_end: formatPDFDate(bill_data.bill_end_date),     // For: <%= bill_end %>
        
        // Billing Summary
        vat_rate_num: vat_percent,  // For: <%= vat_rate_num %>
        billSummary: billSummary,   // For: <% billSummary.forEach... %>
        
        // Totals
        totalBeforeVat: subtotal,  // PASSING AS NUMBER
        totalVat: vat_amount,    // PASSING AS NUMBER
        totalAfterVat: total_bill // PASSING AS NUMBER
    };
    
    const templatePath = path.join(process.cwd(), 'views', 'Admin', 'partials_ad', 'lite_invoice_template.ejs');
    const htmlContent = await ejs.renderFile(templatePath, templateData);

    let browser = browserInstance;
    let localLaunch = !browserInstance; 

    try {
        if (localLaunch) {
            browser = await puppeteer.launch({ 
                headless: 'new',
                args: ['--no-sandbox', '--disable-setuid-sandbox']
            });
        }
        
        const page = await browser.newPage();
        
        await page.setContent(htmlContent, { 
            waitUntil: 'domcontentloaded', 
            timeout: 60000 
        });
        
        // --- MODIFICATION: Set margins to 0 to "fill the PDF" ---
        const pdfBuffer = await page.pdf({ 
            format: 'A4', 
            printBackground: true, 
            margin: { top: '0', right: '0', bottom: '0', left: '0' } // CHANGED
        });

        await page.close(); 
        return pdfBuffer;

    } catch (error) {
        console.error('Puppeteer PDF generation failed:', error);
        return null; 
    } finally {
        // Only close if we launched the browser locally (i.e., for a single download)
        if (browser && localLaunch) { 
            await browser.close();
        }
    }
}

router.post('/api/download-single-invoice', requireStaff, async (req, res) => {
    const bill_data = req.body.bill_data;
    
    if (!bill_data) {
        return res.status(400).json({ status: 'error', message: 'No bill data provided for PDF generation.' });
    }

    try {
        // Passing null means generateInvoicePDFBuffer will launch a local browser instance
        const pdfBuffer = await generateInvoicePDFBuffer(bill_data, null); 
        const filename = `Invoice_${bill_data.device_serialno}_${bill_data.upload_month}.pdf`;

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.send(pdfBuffer);

    } catch (e) {
        console.error('PDF Generation Error (Single Invoice):', e);
        res.status(500).json({ status: 'error', message: `PDF generation failed: ${e.message}` });
    }
});

//=======================================================================================//
// --- PDF GENERATION AND DOWNLOAD APIs (Optimized for Bulk Speed) ---
//=======================================================================================//

router.post('/api/download-invoices', requireStaff, async (req, res) => {
    const bills_data = req.body.bill_data;
    const progressId = req.body.progressId;
    
    if (!bills_data || bills_data.length === 0) {
        return res.status(400).json({ status: 'error', message: 'No bill data provided for PDF generation.' });
    }

    const month = bills_data[0].upload_month || 'unknown_month';
    const zipFilename = `Invoice_Bulk_${month}.zip`;

    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="${zipFilename}"`);

    // --- OPTIMIZATION 1: Set Compression Level to 0 for maximum speed ---
    // Change ZIP_COMPRESSION_LEVEL to '0' (no compression) by default
    const ZIP_COMPRESSION_LEVEL = Number.parseInt(process.env.ZIP_COMPRESSION_LEVEL || '0', 10);
    const archive = archiver('zip', { zlib: { level: ZIP_COMPRESSION_LEVEL } });
    // --- OPTIMIZATION 1 END ---
    
    archive.on('error', function(err) {
        console.error('Archive stream error:', err);
        if (!res.headersSent) {
            res.status(500).send({ error: err.message });
        }
    });

    let skippedInvoices = [];
    const debugPdf = process.env.DEBUG_PDF === 'true';

    // --- OPTIMIZATION 2: Increase Concurrency Limit to 10 by default for faster throughput ---
    const CPU_CORES = require('os').cpus().length;
    const CONCURRENCY_LIMIT = Number.parseInt(process.env.BULK_PDF_CONCURRENCY || (CPU_CORES * 2), 10);
    const limit = pLimit(CONCURRENCY_LIMIT);
    // --- OPTIMIZATION 2 END ---

    let browser; 
    const totalCount = bills_data.length;
    if (progressId) {
        bulkProgress.set(progressId, { processed: 0, total: totalCount, done: false, error: null });
    }

    try {
        archive.pipe(res);

        // --- OPTIMIZATION 3: Launch a SINGLE Puppeteer Instance before the map/limit loop ---
        // This is the key optimization for speed.
        browser = await puppeteer.launch({ 
            headless: 'new',
            args: ['--no-sandbox', '--disable-setuid-sandbox']
        });
        // --- OPTIMIZATION 3 END ---

        const limitedPdfGenerationPromises = bills_data.map(bill => 
            // Pass the single browser instance to the generation function
            limit(async () => {
                const pdfFilename = `Invoice_${bill.device_serialno}_${bill.upload_month}.pdf`;
                let pdfBuffer = null;

                try {
                    // Pass the reusable browser instance
                    pdfBuffer = await generateInvoicePDFBuffer(bill, browser); 
                } catch (e) {
                    console.error(`Concurrent PDF generation failed for ${pdfFilename}:`, e);
                }
                if (progressId) {
                    const state = bulkProgress.get(progressId);
                    if (state) {
                        state.processed = Math.min(state.processed + 1, totalCount);
                        bulkProgress.set(progressId, state);
                    }
                }
                return { pdfBuffer, bill, pdfFilename };
            })
        );

        const results = await Promise.all(limitedPdfGenerationPromises);

        results.forEach(result => {
            const { pdfBuffer, bill, pdfFilename } = result;

            if (!pdfBuffer) {
                console.warn(`Skipping PDF for ${pdfFilename} due to a generation error (returned null).`);
                skippedInvoices.push(`${pdfFilename} - generation error (null)`);
                return;
            }

            try {
                let toAppend = pdfBuffer;

                if (debugPdf) {
                }
                
                try {
                    if (!Buffer.isBuffer(toAppend)) {
                        if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView(toAppend)) {
                            toAppend = Buffer.from(toAppend.buffer, toAppend.byteOffset, toAppend.byteLength);
                        } else if (toAppend && toAppend instanceof ArrayBuffer) {
                            toAppend = Buffer.from(toAppend);
                        } else if (toAppend && typeof toAppend === 'object' && toAppend.data) {
                            toAppend = Buffer.from(toAppend.data);
                        }
                    }
                } catch (convErr) {
                    console.warn(`Could not convert pdfBuffer to Buffer for ${pdfFilename}:`, convErr && convErr.message ? convErr.message : convErr);
                    toAppend = null;
                }

                if (Buffer.isBuffer(toAppend) || (toAppend && typeof toAppend.pipe === 'function')) {
                    archive.append(toAppend, { name: pdfFilename });
                } else {
                    console.warn(`Invalid PDF type for ${pdfFilename}; skipping. Type: ${Object.prototype.toString.call(toAppend)}`);
                    skippedInvoices.push(`${pdfFilename} - invalid type ${Object.prototype.toString.call(toAppend)}`);
                }
            } catch (err) {
                console.error(`Failed adding ${pdfFilename} to archive:`, err && err.message ? err.message : err);
                skippedInvoices.push(`${pdfFilename} - exception ${err && err.message ? err.message : err}`);
            }
            if (progressId) {
                const state = bulkProgress.get(progressId);
                if (state) {
                    state.processed = Math.min(state.processed + 1, totalCount);
                    bulkProgress.set(progressId, state);
                }
            }
        });

        if (skippedInvoices.length > 0) {
            const report = ['The following invoices were skipped during PDF generation:','', ...skippedInvoices].join('\n');
            archive.append(Buffer.from(report, 'utf8'), { name: `SKIPPED_INVICES_${month}.txt` });
        }

    } catch (e) {
        console.error('PDF Generation Error (Bulk ZIP):', e);
        
        try {
            if (!skippedInvoices || skippedInvoices.length === 0) {
                skippedInvoices = [`Bulk generation failed: ${e && e.message ? e.message : e}`];
            }
            const report = ['The following invoices were skipped during PDF generation:','', ...skippedInvoices].join('\n');
            try {
                archive.append(Buffer.from(report, 'utf8'), { name: `SKIPPED_INVICES_${month}.txt` });
            } catch (appendErr) {
                console.error('Failed to append SKIPPED_INVOICES after error:', appendErr && appendErr.message ? appendErr.message : appendErr);
            }
        } catch (reportErr) {
            console.error('Failed to prepare skipped invoices report:', reportErr && reportErr.message ? reportErr.message : reportErr);
        }

    } finally {
        // --- OPTIMIZATION 3: Ensure the single browser instance is closed ---
        if (browser) {
            await browser.close();
        }
        // --- OPTIMIZATION 3 END ---
        try {
            await archive.finalize();
        } catch (finalErr) {
            console.error('Failed to finalize archive after error:', finalErr && finalErr.message ? finalErr.message : finalErr);
            try { archive.abort(); } catch (_) {}
        }
        if (progressId) {
            const state = bulkProgress.get(progressId) || { processed: totalCount, total: totalCount };
            bulkProgress.set(progressId, { ...state, done: true });
            setTimeout(() => bulkProgress.delete(progressId), 5 * 60 * 1000);
        }
    }
});

// Simple polling endpoint for bulk ZIP progress
router.get('/api/bulk-progress/:id', requireStaff, (req, res) => {
    const id = req.params.id;
    const state = bulkProgress.get(id);
    if (!state) {
        return res.status(404).json({ processed: 0, total: 0, done: false });
    }
    res.json(state);
});
//=======================================================================================//
// --- 4. NEW: DASHBOARD API ENDPOINTS ---
//=======================================================================================//

/**
 * Helper function to generate a 12-month array skeleton for charts.
 */
function getMonthSkeleton() {
    return Array.from({ length: 12 }, (_, i) => {
        const month = String(i + 1).padStart(2, '0');
        return {
            month: month,
            revenue: 0,
            consumption: 0,
            devices: [] // Used for specific customer view
        };
    });
}

/**
 * API Endpoint 1: Get all distinct years from the database
 * /api/dashboard/years
 *
 * *** MODIFIED ***
 * Changed TO_CHAR(invoice_date_csv, 'YYYY') to SUBSTRING(upload_month FROM 1 FOR 4)
 * to use the billing period year.
 */
router.get('/api/dashboard/years', requireStaff, async (req, res) => {
    try {
        const query = "SELECT DISTINCT(SUBSTRING(upload_month FROM 1 FOR 4)) as year FROM final_billing_data WHERE upload_month IS NOT NULL ORDER BY year DESC;";
        const { rows } = await pool.query(query);
        const years = rows.map(row => row.year);
        res.json({ status: 'success', years: years });
    } catch (e) {
        console.error('Error fetching dashboard years:', e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

/**
 * API Endpoint 2: Get all customers for a given year
 * /api/dashboard/customers?year=2025
 *
 * *** MODIFIED ***
 * Changed TO_CHAR(invoice_date_csv, 'YYYY') to SUBSTRING(upload_month FROM 1 FOR 4)
 * to filter customers by the billing period year.
 */
router.get('/api/dashboard/customers', requireStaff, async (req, res) => {
    const { year } = req.query;
    
    // THIS IS THE FIX: If no year is provided, get ALL customers from ALL years
    let query;
    let params = [];
    if (year) {
        query = "SELECT DISTINCT customer_name FROM final_billing_data WHERE SUBSTRING(upload_month FROM 1 FOR 4) = $1 ORDER BY customer_name;";
        params.push(year);
    } else {
        query = "SELECT DISTINCT customer_name FROM final_billing_data ORDER BY customer_name;";
    }

    try {
        const { rows } = await pool.query(query, params);
        const customers = rows.map(row => row.customer_name);
        res.json({ status: 'success', customers: customers });
    } catch (e) {
        console.error('Error fetching dashboard customers:', e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});


/**
 * API Endpoint 3: Get all dashboard data (KPIs, Charts)
 * /api/dashboard/data
 *
 * *** MODIFIED ***
 * 1. Changed year filter from TO_CHAR(invoice_date_csv, 'YYYY') to SUBSTRING(upload_month FROM 1 FOR 4)
 * 2. Changed 'all' chart grouping from TO_CHAR(invoice_date_csv, 'MM') to SUBSTRING(upload_month FROM 6 FOR 2)
 * 3. Changed 'specific' chart month from TO_CHAR(invoice_date_csv, 'MM') to SUBSTRING(upload_month FROM 6 FOR 2)
 */
router.get('/api/dashboard/data', requireStaff, async (req, res) => {
    // Year and customer are now optional
    const { year, customer } = req.query;

    const client = await pool.connect();
    try {
        let kpiData = {};
        let chartData = getMonthSkeleton(); // Start with 12 empty months
        let viewType = 'all'; // Default to 'all'
        
        let kpiParams = [];
        let kpiWhereClause = 'WHERE 1=1';
        
        let chartParams = [];
        let chartWhereClause = 'WHERE 1=1';

        // Check if year is provided AND is a valid year (not 'All Years')
        if (year) {
            // *** CHANGE 1: Use upload_month for year filter ***
            kpiWhereClause += ` AND SUBSTRING(upload_month FROM 1 FOR 4) = $${kpiParams.length + 1}`;
            kpiParams.push(year);
            chartWhereClause += ` AND SUBSTRING(upload_month FROM 1 FOR 4) = $${chartParams.length + 1}`;
            chartParams.push(year);
        }
        
        // Check if customer is provided AND is a specific customer
        if (customer && customer !== 'All Customers') {
            viewType = 'specific';
            kpiWhereClause += ` AND customer_name = $${kpiParams.length + 1}`;
            kpiParams.push(customer);
            chartWhereClause += ` AND customer_name = $${chartParams.length + 1}`;
            chartParams.push(customer);
        }

        // --- 1. Get KPIs ---
        const kpiQueryText = `
            SELECT 
                SUM(total_bill_amount_sar) as total_revenue,
                SUM(net_consumption_m3) as total_consumption,
                COUNT(id) as total_bills,
                AVG(total_bill_amount_sar) as avg_bill
            FROM final_billing_data
            ${kpiWhereClause}
        `;
        const kpiResult = await client.query(kpiQueryText, kpiParams);
        kpiData = kpiResult.rows[0];

        // --- 2. Get Chart Data ---
        if (viewType === 'all') {
            // === SCENARIO: ALL CUSTOMERS (for a given year, or all time) ===
            const chartQuery = {
                text: `
                    SELECT 
                        -- *** CHANGE 2: Use upload_month for month grouping ***
                        SUBSTRING(upload_month FROM 6 FOR 2) as month,
                        SUM(total_bill_amount_sar) as revenue,
                        SUM(net_consumption_m3) as consumption
                    FROM final_billing_data
                    ${chartWhereClause}
                    GROUP BY month
                    ORDER BY month;
                `,
                params: chartParams
            };
            const chartResult = await client.query(chartQuery.text, chartQuery.params);
            
            chartResult.rows.forEach(row => {
                const monthIndex = parseInt(row.month, 10) - 1;
                if (chartData[monthIndex]) {
                    chartData[monthIndex].revenue = parseFloat(row.revenue);
                    chartData[monthIndex].consumption = parseFloat(row.consumption);
                }
            });

        } else {
            // === SCENARIO: SPECIFIC CUSTOMER (for a given year, or all time) ===
            const chartQuery = {
                text: `
                    SELECT 
                        -- *** CHANGE 3: Use upload_month for month grouping ***
                        SUBSTRING(upload_month FROM 6 FOR 2) as month,
                        device_serialno,
                        total_bill_amount_sar as revenue,
                        net_consumption_m3 as consumption
                    FROM final_billing_data
                    ${chartWhereClause}
                    ORDER BY month, device_serialno;
                `,
                params: chartParams
            };
            const chartResult = await client.query(chartQuery.text, chartQuery.params);
            
            chartResult.rows.forEach(row => {
                const monthIndex = parseInt(row.month, 10) - 1;
                if (chartData[monthIndex]) {
                    chartData[monthIndex].devices.push({
                        serial: row.device_serialno,
                        revenue: parseFloat(row.revenue),
                        consumption: parseFloat(row.consumption)
                    });
                }
            });
        }

        res.json({
            status: 'success',
            viewType: viewType,
            kpis: {
                total_revenue: parseFloat(kpiData.total_revenue || 0).toFixed(2),
                total_consumption: parseFloat(kpiData.total_consumption || 0).toFixed(2),
                total_bills: parseInt(kpiData.total_bills || 0),
                avg_bill: parseFloat(kpiData.avg_bill || 0).toFixed(2)
            },
            chartData: chartData
        });

    } catch (e) {
        console.error('Error fetching dashboard data:', e);
        res.status(500).json({ status: 'error', message: e.message });
    } finally {
        client.release();
    }
});


//=======================================================================================//
// --- 5. NEW: COMPANY SETTINGS API ---
//=======================================================================================//

// Multer config for logo upload
const logoStorage = multer.diskStorage({
    destination: function (req, file, cb) {
        // We save logos in 'public/uploads/'
        // The 'public' folder is static, so 'uploads/logo.png' will be accessible
        const uploadPath = path.join(__dirname, 'public', 'uploads');
        
        // Ensure the directory exists
        fs.mkdir(uploadPath, { recursive: true }, (err) => {
            if (err) {
                console.error("Failed to create upload directory", err);
                return cb(err);
            }
            cb(null, uploadPath);
        });
    },
    filename: function (req, file, cb) {
        // We'll just name it 'company-logo' with the original extension
        const newFilename = 'company-logo' + path.extname(file.originalname);
        cb(null, newFilename);
    }
});

const logoUpload = multer({ 
    storage: logoStorage,
    limits: { fileSize: 2 * 1024 * 1024 }, // 2MB limit
    fileFilter: (req, file, cb) => {
        // Allow only images
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'), false);
        }
    }
});

// GET Route: Load the company settings
router.get('/api/company-settings', requireStaff, async (req, res) => {
    const client = await pool.connect();
    try {
        const queryText = "SELECT * FROM company_settings WHERE id = 1";
        const result = await client.query(queryText);

        let data = {};
        if (result.rows.length > 0) {
            data = result.rows[0]; // Get the first (and only) row
        }

        // Send the data in the format the frontend expects
        res.json({ status: 'success', data: data });

    } catch (e) {
        console.error('Error fetching company settings:', e);
        res.status(500).json({ status: 'error', message: e.message });
    } finally {
        client.release();
    }
});


// 
// ==========================================================================
// --- THIS IS THE CORRECTED POST ROUTE ---
// ==========================================================================
//
// ==========================================================================
// --- THIS IS THE CORRECTED POST ROUTE ---
// ==========================================================================
//
router.post('/api/company-settings', requireWrite, logoUpload.single('logo-upload'), async (req, res) => {
    
    // Get ALL fields from the form body
    const { 
        company_name, address, city, postal_code, 
        phone, email, website, about,
        default_language, currency, vat_rate,
        license_type, license_status,
        number_of_devices, expiry_date // <-- ADD THESE TWO
    } = req.body;
    
    let logoUrl = req.body.existing_logo_url;
    
    if (req.file) {
        // Case 1: New logo was uploaded. Overwrite.
        logoUrl = '/uploads/' + req.file.filename;
    } else if (req.body.existing_logo_url === "") {
        // Case 2: 'X' was clicked. Set to null.
        logoUrl = null;
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        // --- 🥇 POSTGRESQL UPSERT LOGIC ---
        const queryText = `
            INSERT INTO company_settings (
                id, company_name, logo_url, address, city, postal_code, 
                phone, email, website, about, default_language, currency, 
                vat_rate, license_type, license_status,
                number_of_devices, expiry_date 
            )
            VALUES (
                1, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
                $15, $16
            )
            ON CONFLICT (id) DO UPDATE SET
                company_name = EXCLUDED.company_name, 
                logo_url = EXCLUDED.logo_url, 
                address = EXCLUDED.address, 
                city = EXCLUDED.city, 
                postal_code = EXCLUDED.postal_code, 
                phone = EXCLUDED.phone, 
                email = EXCLUDED.email, 
                website = EXCLUDED.website, 
                about = EXCLUDED.about,
                default_language = EXCLUDED.default_language,
                currency = EXCLUDED.currency,
                vat_rate = EXCLUDED.vat_rate,
                license_type = EXCLUDED.license_type,
                license_status = EXCLUDED.license_status,
                number_of_devices = EXCLUDED.number_of_devices, 
                expiry_date = EXCLUDED.expiry_date 
        `;
        
        const queryParams = [
            company_name, logoUrl, address, city, postal_code,
            phone, email, website, about,
            default_language, currency, vat_rate,
            license_type, license_status,
            number_of_devices, expiry_date // <-- ADD THESE TWO
        ];

        // Execute the single UPSERT query
        await client.query(queryText, queryParams);
        await client.query('COMMIT');
        
        res.json({ status: 'success', message: 'Settings saved successfully!', newLogoUrl: logoUrl });

    } catch (e) {
        await client.query('ROLLBACK');
        console.error('Error saving company settings:', e);
        res.status(500).json({ status: 'error', message: e.message });
    } finally {
        client.release();
    }
});



//=======================================================================================//
// --- Export the router so index.js can use it ---
//=======================================================================================//
module.exports = router;