require('dotenv').config();
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const pool = new Pool(); 

async function seedDatabase() {
  const client = await pool.connect();
  console.log('Connecting to database to seed data...');

  try {
    await client.query('BEGIN');

    // --- 1. Create Staff Users ---
    console.log('Seeding staff_users...');
    
    // 👇 CHANGE YOUR PASSWORD HERE 👇
    const masterHash = await bcrypt.hash('master123', 12); 
    const operatorHash = await bcrypt.hash('operator123', 12);
    
    // Create a Master user
    await client.query(
      `INSERT INTO staff_users (username, password_hash, role, is_active) 
       VALUES ($1, $2, 'master', true) 
       ON CONFLICT (username) DO NOTHING`, 
       ['master_user', masterHash] // 👈 CHANGE 'master_user' TO YOUR USERNAME
    );

    // Create an Operator user
    await client.query(
      `INSERT INTO staff_users (username, password_hash, role, is_active) 
       VALUES ('operator_user', $1, 'operator', true) 
       ON CONFLICT (username) DO NOTHING`, [operatorHash]
    );
    console.log('Staff users seeded.');

    // --- 2. Seed Company Settings ---
    console.log('Seeding company_settings...');
    // Note: Ensure you have a logo at this path or update it
    await client.query(
      `INSERT INTO company_settings (id, company_name, logo_url, address, city) 
       VALUES (1, 'Reva Zone Demo', '/uploads/company-logo.png', '123 Demo Street', 'Riyadh') 
       ON CONFLICT (id) DO UPDATE SET 
         company_name = EXCLUDED.company_name, logo_url = EXCLUDED.logo_url`
    );

    // --- 3. Seed Reference Data ---
    console.log('Seeding reference_data...');
    await client.query(
      `INSERT INTO reference_data (owner_id, device_serialno, customer_name) VALUES
       (1, 'METER-001', 'Al-Othaim Markets'),
       (1, 'METER-002', 'Panda Retail'),
       (1, 'METER-003', 'Jarir Bookstore')
       ON CONFLICT DO NOTHING`
    );
    
    // --- 4. Seed Billing Data ---
    console.log('Seeding final_billing_data...');
    await client.query(
      `INSERT INTO final_billing_data (upload_month, device_serialno, customer_name, net_consumption_m3, total_bill_amount_sar, vat_percent, upload_tariff_sar) VALUES
       ('2025-10', 'METER-001', 'Al-Othaim Markets', 150.5, 850.25, 15, 5.0),
       ('2025-10', 'METER-002', 'Panda Retail', 220.0, 1200.00, 15, 5.0),
       ('2025-09', 'METER-001', 'Al-Othaim Markets', 140.0, 790.10, 15, 5.0)
       ON CONFLICT DO NOTHING`
    );

    await client.query('COMMIT');
    console.log('✅ Database seeding complete!');

  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Database seeding failed:', e);
  } finally {
    client.release();
    pool.end();
  }
}

seedDatabase();