#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    print_error "This script must be run from the project root directory"
    exit 1
fi

# Function to get current version from Cargo.toml
get_current_version() {
    grep '^version = ' Cargo.toml | sed 's/version = "\(.*\)"/\1/'
}

# Function to validate version format
validate_version() {
    if [[ ! $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        print_error "Invalid version format. Use semantic versioning (e.g., 1.0.0)"
        return 1
    fi
}

# Function to update version in Cargo.toml
update_version() {
    local new_version=$1
    print_info "Updating version to $new_version in Cargo.toml"
    
    # Update version in Cargo.toml
    sed -i.bak "s/^version = \".*\"/version = \"$new_version\"/" Cargo.toml
    rm Cargo.toml.bak
    
    print_success "Version updated to $new_version"
}

# Function to run tests
run_tests() {
    print_info "Running tests..."
    cargo test
    print_success "All tests passed"
}

# Function to build release
build_release() {
    print_info "Building release..."
    cargo build --release
    print_success "Release build completed"
}

# Function to create git tag
create_git_tag() {
    local version=$1
    local tag_name="v$version"
    local current_branch=$(git branch --show-current)
    
    print_info "Creating git tag $tag_name"
    
    # Add changes
    git add Cargo.toml
    git commit -m "Release v$version"
    
    # Create tag
    git tag -a "$tag_name" -m "Release version $version"
    
    print_success "Git tag $tag_name created"
    print_info "Push with: git push origin $current_branch && git push origin $tag_name"
}

# Main function
main() {
    print_info "🚀 Starknet Remote Signer Release Script"
    echo ""
    
    current_version=$(get_current_version)
    print_info "Current version: $current_version"
    
    # Get new version from user
    echo ""
    read -p "Enter new version (e.g., 0.2.0): " new_version
    
    # Validate version
    if ! validate_version "$new_version"; then
        exit 1
    fi
    
    # Check if version is newer
    if [ "$new_version" = "$current_version" ]; then
        print_error "New version must be different from current version"
        exit 1
    fi
    
    print_warning "This will:"
    echo "  1. Update version to $new_version"
    echo "  2. Run tests"
    echo "  3. Build release"
    echo "  4. Create git commit and tag"
    echo ""
    read -p "Continue? (y/N): " confirm
    
    if [[ $confirm != [yY] ]]; then
        print_info "Release cancelled"
        exit 0
    fi
    
    # Execute release steps
    update_version "$new_version"
    run_tests
    build_release
    create_git_tag "$new_version"
    
    echo ""
    print_success "🎉 Release v$new_version prepared!"
    local current_branch=$(git branch --show-current)
    print_info "Next steps:"
    echo "  1. Review changes: git show"
    echo "  2. Push to GitHub: git push origin $current_branch && git push origin v$new_version"
    echo "  3. GitHub Actions will automatically create the release"
    echo ""
    print_warning "Note: The GitHub release will be created automatically when you push the tag"
}

# Check for help flag
if [[ $1 == "-h" || $1 == "--help" ]]; then
    echo "Starknet Remote Signer Release Script"
    echo ""
    echo "Usage: $0"
    echo ""
    echo "This script will:"
    echo "  - Update the version in Cargo.toml"
    echo "  - Run tests to ensure everything works"
    echo "  - Build a release version"
    echo "  - Create a git commit and tag"
    echo ""
    echo "After running this script, push the changes and tag to GitHub"
    echo "to trigger the automated release process."
    exit 0
fi

main 