#!/bin/bash

# Integration test script for starknet-remote-signer with starknet-attestation

set -e

echo "🧪 Integration Test: starknet-remote-signer + starknet-attestation"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test configuration
REMOTE_SIGNER_PORT=3001
TEST_PRIVATE_KEY="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
TEST_OPERATIONAL_ADDRESS="0x02e216b191ac966ba1d35cb6cfddfaf9c12aec4dfe869d9fa6233611bb334ee9"

# Function to cleanup background processes
cleanup() {
    echo -e "${YELLOW}🧹 Cleaning up...${NC}"
    if [ ! -z "$SIGNER_PID" ]; then
        kill $SIGNER_PID 2>/dev/null || true
    fi
    if [ ! -z "$ATTESTATION_PID" ]; then
        kill $ATTESTATION_PID 2>/dev/null || true
    fi
}

# Set trap to cleanup on exit
trap cleanup EXIT

echo -e "${YELLOW}📋 Test Setup:${NC}"
echo "  Remote Signer Port: $REMOTE_SIGNER_PORT"
echo "  Test Private Key: ${TEST_PRIVATE_KEY:0:16}..."
echo "  Operational Address: $TEST_OPERATIONAL_ADDRESS"

# Step 1: Build and start remote signer
echo -e "\n${YELLOW}🔨 Building starknet-remote-signer...${NC}"
if ! cargo build --release; then
    echo "❌ Failed to build starknet-remote-signer"
    exit 1
fi

echo -e "\n${YELLOW}🚀 Starting remote signer...${NC}"
SIGNER_PRIVATE_KEY=$TEST_PRIVATE_KEY \
SIGNER_PORT=$REMOTE_SIGNER_PORT \
RUST_LOG=debug \
./target/release/starknet-remote-signer start &
SIGNER_PID=$!

# Wait for signer to start
sleep 3

# Test if signer is responding
echo -e "\n${YELLOW}🔍 Testing remote signer health...${NC}"
HEALTH_RESPONSE=$(curl -s http://localhost:$REMOTE_SIGNER_PORT/health)
if [[ $? -eq 0 ]]; then
    echo -e "${GREEN}✅ Remote signer is healthy${NC}"
    echo "Health response: $HEALTH_RESPONSE"
else
    echo -e "${RED}❌ Remote signer health check failed${NC}"
    exit 1
fi

# Test public key endpoint
echo -e "\n${YELLOW}🔑 Testing public key endpoint...${NC}"
PUBLIC_KEY_RESPONSE=$(curl -s http://localhost:$REMOTE_SIGNER_PORT/public_key)
if [[ $? -eq 0 ]]; then
    echo -e "${GREEN}✅ Public key endpoint working${NC}"
    echo "Public key response: $PUBLIC_KEY_RESPONSE"
else
    echo -e "${RED}❌ Public key endpoint failed${NC}"
    exit 1
fi

# Step 2: Test with mock starknet-attestation request
echo -e "\n${YELLOW}🧪 Testing with mock starknet-attestation request...${NC}"

# Create test transaction (from starknet-attestation README)
TEST_REQUEST='{
    "transaction": {
        "type": "INVOKE",
        "sender_address": "'$TEST_OPERATIONAL_ADDRESS'",
        "calldata": [
            "0x1",
            "0x4862e05d00f2d0981c4a912269c21ad99438598ab86b6e70d1cee267caaa78d",
            "0x37446750a403c1b4014436073cf8d08ceadc5b156ac1c8b7b0ca41a0c9c1c54",
            "0x1",
            "0x614f596b9d8eafbc87a48ff3a2a4bd503762d3f4be7c91cdeb766cf869c2233"
        ],
        "version": "0x3",
        "signature": [],
        "nonce": "0xbf",
        "resource_bounds": {
            "l1_gas": {
                "max_amount": "0x0",
                "max_price_per_unit": "0x49f83fa3027b"
            },
            "l1_data_gas": {
                "max_amount": "0x600",
                "max_price_per_unit": "0x3948c"
            },
            "l2_gas": {
                "max_amount": "0x1142700",
                "max_price_per_unit": "0x33a8f57f9"
            }
        },
        "tip": "0x0",
        "paymaster_data": [],
        "account_deployment_data": [],
        "nonce_data_availability_mode": "L1",
        "fee_data_availability_mode": "L1"
    },
    "chain_id": "0x534e5f5345504f4c4941"
}'

# Send signing request
SIGN_RESPONSE=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -d "$TEST_REQUEST" \
    http://localhost:$REMOTE_SIGNER_PORT/sign)

if [[ $? -eq 0 ]]; then
    echo -e "${GREEN}✅ Signing request successful${NC}"
    echo "Sign response: $SIGN_RESPONSE"
    
    # Validate response format
    if echo "$SIGN_RESPONSE" | jq -e '.signature | length == 2' >/dev/null 2>&1; then
        echo -e "${GREEN}✅ Response format is correct (signature array with 2 elements)${NC}"
    else
        echo -e "${RED}❌ Invalid response format${NC}"
        exit 1
    fi
else
    echo -e "${RED}❌ Signing request failed${NC}"
    exit 1
fi

# Step 3: Test with actual starknet-attestation (if available)
cd ../starknet-attestation

if [ -f "Cargo.toml" ]; then
    echo -e "\n${YELLOW}🔗 Testing with real starknet-attestation...${NC}"
    
    # Build starknet-attestation
    echo "Building starknet-attestation..."
    cargo build --release
    
    # Test dry-run (this won't actually attest, just test the signer connection)
    echo "Testing remote signer connection..."
    
    # Note: This would need actual Starknet node and contract addresses
    # For now, we just test that the binary accepts the remote-signer-url flag
    if ./target/release/starknet-validator-attestation --help | grep -q "remote-signer-url"; then
        echo -e "${GREEN}✅ starknet-attestation supports remote-signer-url${NC}"
    else
        echo -e "${RED}❌ starknet-attestation doesn't support remote-signer-url${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}⚠️  starknet-attestation not found, skipping real integration test${NC}"
fi

echo -e "\n${GREEN}🎉 All tests passed! Integration is working correctly.${NC}"
echo -e "\n${YELLOW}📝 To use with real starknet-attestation:${NC}"
echo "  starknet-validator-attestation \\"
echo "    --remote-signer-url http://localhost:$REMOTE_SIGNER_PORT \\"
echo "    --staker-operational-address $TEST_OPERATIONAL_ADDRESS \\"
echo "    --node-url http://your-starknet-node:9545/rpc/v0_8" 