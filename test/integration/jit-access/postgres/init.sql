-- Create role with login
CREATE ROLE supabase_admin WITH LOGIN PASSWORD '56lRXbZStSL9vY3cJJxLZd5wQxpWvfl9';
-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE postgres TO supabase_admin;
