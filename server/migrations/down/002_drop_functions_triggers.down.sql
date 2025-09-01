-- Drop triggers
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP TRIGGER IF EXISTS update_clients_updated_at ON clients;

-- Drop function
DROP FUNCTION IF EXISTS update_updated_at_column();