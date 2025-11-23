// ===================================
// New File: pdfWorker.js
// ===================================
const { parentPort } = require('worker_threads');
const path = require('path');
const ejs = require('ejs');

// The function is copied from backend.js but simplified for the worker context.
// NOTE: It now receives the browser instance/page from the main thread via the message.

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

async function generateInvoicePDFBuffer(bill_data, browser) {
    // This function is exactly the same as the one in backend.js,
    // but relies on 'browser' being passed in from the main thread.
    // ... [Content of your generateInvoicePDFBuffer function] ...
    
    // START: Simplified generation logic for Worker
    const consumption = parseFloat(bill_data.net_consumption_m3);
    const tariff = parseFloat(bill_data.upload_tariff_sar);
    const vat_percent = parseFloat(bill_data.vat_percent);

    const consumption_charge = consumption * tariff;

    let total_other_charges = 0;
    const charges = [];

    if (bill_data.csv_charge_1_rate > 0) {
        const rate = parseFloat(bill_data.csv_charge_1_rate);
        charges.push({ desc: bill_data.csv_charge_1_desc, rate: rate.toFixed(2) });
        total_other_charges += rate;
    }
    // ... [Add remaining charge logic] ...
    if (bill_data.csv_charge_2_rate > 0) {
        const rate = parseFloat(bill_data.csv_charge_2_rate);
        charges.push({ desc: bill_data.csv_charge_2_desc, rate: rate.toFixed(2) });
        total_other_charges += rate;
    }
    if (bill_data.csv_charge_3_rate > 0) {
        const rate = parseFloat(bill_data.csv_charge_3_rate);
        charges.push({ desc: bill_data.csv_charge_3_desc, rate: rate.toFixed(2) });
        total_other_charges += rate;
    }

    const subtotal = consumption_charge + total_other_charges;
    const vat_amount = subtotal * (vat_percent / 100);
    const total_bill = parseFloat(bill_data.total_bill_amount_sar); 

    const templateData = {
        bill: bill_data,
        start_date: formatPDFDate(bill_data.bill_start_date),
        end_date: formatPDFDate(bill_data.bill_end_date),
        invoice_date: formatPDFDate(bill_data.invoice_date_csv),
        consumption_m3: consumption.toFixed(2),
        tariff: tariff.toFixed(4),
        consumption_charge: consumption_charge.toFixed(2),
        charges: charges,
        subtotal: subtotal.toFixed(2),
        vat_percent: vat_percent.toFixed(2),
        vat_amount: vat_amount.toFixed(2),
        total_bill: total_bill.toFixed(2)
    };
    
    // NOTE: This path needs to be absolute for the worker.
    const templatePath = path.join(process.cwd(), 'views', 'Admin', 'partials_ad', 'lite_invoice_template.ejs');
    const htmlContent = await ejs.renderFile(templatePath, templateData);

    const page = await browser.newPage();
    
    await page.setContent(htmlContent, { 
        waitUntil: 'domcontentloaded', 
        timeout: 60000 
    });
    
    const pdfBuffer = await page.pdf({ 
        format: 'A4', 
        printBackground: true, 
        margin: { top: '0.5in', right: '0.5in', bottom: '0.5in', left: '0.5in' }
    });

    await page.close(); // Close the page, keep the browser open.
    return pdfBuffer;
    // END: Simplified generation logic for Worker
}

// Receive message from main thread
parentPort.on('message', async (message) => {
    const { bill_data, browser } = message;
    try {
        const pdfBuffer = await generateInvoicePDFBuffer(bill_data, browser);
        parentPort.postMessage({ status: 'success', pdfBuffer: pdfBuffer }, [pdfBuffer]); // Transfer buffer back
    } catch (error) {
        parentPort.postMessage({ status: 'error', message: error.message });
    }
});// ===================================
// New File: pdfWorker.js
// ===================================
const { parentPort } = require('worker_threads');
const path = require('path');
const ejs = require('ejs');

// The function is copied from backend.js but simplified for the worker context.
// NOTE: It now receives the browser instance/page from the main thread via the message.

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

async function generateInvoicePDFBuffer(bill_data, browser) {
    // This function is exactly the same as the one in backend.js,
    // but relies on 'browser' being passed in from the main thread.
    // ... [Content of your generateInvoicePDFBuffer function] ...
    
    // START: Simplified generation logic for Worker
    const consumption = parseFloat(bill_data.net_consumption_m3);
    const tariff = parseFloat(bill_data.upload_tariff_sar);
    const vat_percent = parseFloat(bill_data.vat_percent);

    const consumption_charge = consumption * tariff;

    let total_other_charges = 0;
    const charges = [];

    if (bill_data.csv_charge_1_rate > 0) {
        const rate = parseFloat(bill_data.csv_charge_1_rate);
        charges.push({ desc: bill_data.csv_charge_1_desc, rate: rate.toFixed(2) });
        total_other_charges += rate;
    }
    // ... [Add remaining charge logic] ...
    if (bill_data.csv_charge_2_rate > 0) {
        const rate = parseFloat(bill_data.csv_charge_2_rate);
        charges.push({ desc: bill_data.csv_charge_2_desc, rate: rate.toFixed(2) });
        total_other_charges += rate;
    }
    if (bill_data.csv_charge_3_rate > 0) {
        const rate = parseFloat(bill_data.csv_charge_3_rate);
        charges.push({ desc: bill_data.csv_charge_3_desc, rate: rate.toFixed(2) });
        total_other_charges += rate;
    }

    const subtotal = consumption_charge + total_other_charges;
    const vat_amount = subtotal * (vat_percent / 100);
    const total_bill = parseFloat(bill_data.total_bill_amount_sar); 

    const templateData = {
        bill: bill_data,
        start_date: formatPDFDate(bill_data.bill_start_date),
        end_date: formatPDFDate(bill_data.bill_end_date),
        invoice_date: formatPDFDate(bill_data.invoice_date_csv),
        consumption_m3: consumption.toFixed(2),
        tariff: tariff.toFixed(4),
        consumption_charge: consumption_charge.toFixed(2),
        charges: charges,
        subtotal: subtotal.toFixed(2),
        vat_percent: vat_percent.toFixed(2),
        vat_amount: vat_amount.toFixed(2),
        total_bill: total_bill.toFixed(2)
    };
    
    // NOTE: This path needs to be absolute for the worker.
    const templatePath = path.join(process.cwd(), 'views', 'Admin', 'partials_ad', 'lite_invoice_template.ejs');
    const htmlContent = await ejs.renderFile(templatePath, templateData);

    const page = await browser.newPage();
    
    await page.setContent(htmlContent, { 
        waitUntil: 'domcontentloaded', 
        timeout: 60000 
    });
    
    const pdfBuffer = await page.pdf({ 
        format: 'A4', 
        printBackground: true, 
        margin: { top: '0.5in', right: '0.5in', bottom: '0.5in', left: '0.5in' }
    });

    await page.close(); // Close the page, keep the browser open.
    return pdfBuffer;
    // END: Simplified generation logic for Worker
}

// Receive message from main thread
parentPort.on('message', async (message) => {
    const { bill_data, browser } = message;
    try {
        const pdfBuffer = await generateInvoicePDFBuffer(bill_data, browser);
        parentPort.postMessage({ status: 'success', pdfBuffer: pdfBuffer }, [pdfBuffer]); // Transfer buffer back
    } catch (error) {
        parentPort.postMessage({ status: 'error', message: error.message });
    }
});