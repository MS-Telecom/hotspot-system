const { createClient } = require('@supabase/supabase-client');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

async function runMigration() {
    const sql = fs.readFileSync(path.join(__dirname, 'full_migration.sql'), 'utf8');
    
    // O Supabase client não tem um método direto para rodar SQL arbitrário por segurança.
    // No entanto, podemos usar a API de RPC se houver uma função definida, 
    // ou tentar rodar via psql se conseguirmos a conexão.
    // Como o psql falhou, vamos tentar usar o client para verificar o schema primeiro.
    
    console.log('Verificando conexão com Supabase...');
    const { data, error } = await supabase.from('free_trials').select('count').limit(1);
    
    if (error) {
        console.error('Erro de conexão:', error.message);
        process.exit(1);
    }
    
    console.log('Conexão OK. Como o client não suporta SQL direto, a migração deve ser feita via Dashboard ou PSQL.');
    console.log('Vou tentar rodar via PSQL novamente com parâmetros corrigidos.');
}

runMigration();
