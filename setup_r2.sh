#!/bin/bash

echo "🚀 Cloudflare R2 + MLS Server Setup"
echo "===================================="
echo ""

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "📝 Creating .env from template..."
    cp .env.example .env
    echo "✅ .env created"
    echo ""
    echo "⚠️  IMPORTANT: Edit .env with your R2 credentials!"
    echo "   1. Go to https://dash.cloudflare.com/ → R2"
    echo "   2. Create bucket: catbird-messages"
    echo "   3. Generate API token"
    echo "   4. Update .env with your credentials"
    echo ""
    read -p "Press enter after configuring .env..."
fi

# Check if R2 credentials are configured
source .env 2>/dev/null

if [ -z "$R2_ACCESS_KEY_ID" ] || [ "$R2_ACCESS_KEY_ID" = "your_r2_access_key_id" ]; then
    echo "❌ R2 credentials not configured in .env"
    echo ""
    echo "Please update .env with:"
    echo "  - R2_ENDPOINT"
    echo "  - R2_BUCKET"
    echo "  - R2_ACCESS_KEY_ID"
    echo "  - R2_SECRET_ACCESS_KEY"
    echo ""
    echo "See R2_SETUP.md for detailed instructions"
    exit 1
fi

echo "✅ R2 credentials found"
echo ""

# Update Rust
echo "🔧 Updating Rust toolchain..."
rustup update stable
echo "✅ Rust updated"
echo ""

# Run database migrations
echo "🗄️  Running database migrations..."
cd server
sqlx migrate run
echo "✅ Migrations complete"
echo ""

# Build server
echo "🔨 Building server..."
cargo build --release
if [ $? -eq 0 ]; then
    echo "✅ Build successful"
else
    echo "❌ Build failed"
    exit 1
fi
echo ""

# Success message
echo "🎉 Setup complete!"
echo ""
echo "Next steps:"
echo "  1. Start the server: cd server && cargo run"
echo "  2. Test the API: curl http://localhost:3000/health"
echo "  3. Store a message: curl -X POST http://localhost:3000/api/v1/messages ..."
echo ""
echo "See CLOUDFLARE_R2_MIGRATION_SUMMARY.md for usage examples!"
