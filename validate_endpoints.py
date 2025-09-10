"""
Comprehensive Endpoint Validation Script for AuthX
Tests all endpoints for potential runtime errors and validates schemas.
"""
import asyncio
import logging
from typing import Dict, Any, List
import importlib
import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

logger = logging.getLogger(__name__)

async def validate_endpoints() -> Dict[str, Any]:
    """Validate all AuthX endpoints for potential errors."""

    validation_results = {
        "status": "success",
        "endpoints_validated": 0,
        "issues_found": [],
        "warnings": [],
        "summary": {}
    }

    print("🔍 AuthX Endpoint Validation")
    print("=" * 50)

    # List of endpoint modules to validate
    endpoint_modules = [
        "app.api.v1.auth",
        "app.api.v1.user",
        "app.api.v1.organization",
        "app.api.v1.role",
        "app.api.v1.location",
        "app.api.v1.admin",
        "app.api.v1.audit",
        "app.api.v1.operations",
        "app.api.v1.health"
    ]

    for module_name in endpoint_modules:
        try:
            print(f"\n📋 Validating {module_name}...")

            # Try to import the module
            module = importlib.import_module(module_name)

            # Check if router exists
            if not hasattr(module, 'router'):
                validation_results["issues_found"].append(
                    f"{module_name}: Missing 'router' attribute"
                )
                continue

            router = module.router

            # Count routes
            route_count = len(router.routes)
            validation_results["endpoints_validated"] += route_count

            # Validate routes
            route_issues = []
            for route in router.routes:
                if hasattr(route, 'endpoint'):
                    endpoint_name = route.endpoint.__name__

                    # Check for common issues
                    if not hasattr(route, 'response_model') and 'get' in route.methods:
                        route_issues.append(f"GET {endpoint_name}: Missing response_model")

                    # Check for proper error handling
                    try:
                        import inspect
                        source = inspect.getsource(route.endpoint)

                        if 'HTTPException' not in source and 'raise' not in source:
                            route_issues.append(f"{endpoint_name}: Missing error handling")

                        if '.model_validate(' not in source and 'from_orm' in source:
                            route_issues.append(f"{endpoint_name}: Using deprecated from_orm instead of model_validate")
                    except:
                        pass

            if route_issues:
                validation_results["issues_found"].extend([
                    f"{module_name}: {issue}" for issue in route_issues
                ])

            validation_results["summary"][module_name] = {
                "routes": route_count,
                "issues": len(route_issues),
                "status": "✅ PASS" if len(route_issues) == 0 else "⚠️ ISSUES"
            }

            print(f"   Routes: {route_count}")
            print(f"   Issues: {len(route_issues)}")
            print(f"   Status: {'✅ PASS' if len(route_issues) == 0 else '⚠️ ISSUES'}")

        except ImportError as e:
            error_msg = f"{module_name}: Import error - {str(e)}"
            validation_results["issues_found"].append(error_msg)
            print(f"   ❌ IMPORT ERROR: {str(e)}")

        except Exception as e:
            error_msg = f"{module_name}: Validation error - {str(e)}"
            validation_results["issues_found"].append(error_msg)
            print(f"   ❌ ERROR: {str(e)}")

    # Schema validation
    print(f"\n🏗️ Validating Pydantic Schemas...")
    schema_modules = [
        "app.schemas.auth",
        "app.schemas.user",
        "app.schemas.organization",
        "app.schemas.role",
        "app.schemas.location"
    ]

    schema_issues = []
    for schema_module in schema_modules:
        try:
            module = importlib.import_module(schema_module)

            # Check for common Pydantic v2 issues
            module_source = str(module.__file__)
            with open(module_source, 'r') as f:
                content = f.read()

            if 'from_orm' in content and 'model_validate' not in content:
                schema_issues.append(f"{schema_module}: Still using deprecated from_orm")

            if 'Config:' in content and 'from_attributes = True' not in content:
                schema_issues.append(f"{schema_module}: Missing from_attributes = True in Config")

        except Exception as e:
            schema_issues.append(f"{schema_module}: {str(e)}")

    validation_results["issues_found"].extend(schema_issues)
    print(f"   Schema issues found: {len(schema_issues)}")

    # Service validation
    print(f"\n⚙️ Validating Services...")
    service_modules = [
        "app.services.auth_service",
        "app.services.user_service",
        "app.services.organization_service",
        "app.services.role_service",
        "app.services.email_service"
    ]

    service_issues = []
    for service_module in service_modules:
        try:
            importlib.import_module(service_module)
        except ImportError as e:
            service_issues.append(f"{service_module}: Import error - {str(e)}")

    validation_results["issues_found"].extend(service_issues)
    print(f"   Service issues found: {len(service_issues)}")

    # Final status
    if validation_results["issues_found"]:
        validation_results["status"] = "issues_found"

    print(f"\n📊 Validation Summary:")
    print(f"   Total Endpoints: {validation_results['endpoints_validated']}")
    print(f"   Issues Found: {len(validation_results['issues_found'])}")
    print(f"   Status: {'✅ PASS' if validation_results['status'] == 'success' else '⚠️ ISSUES FOUND'}")

    if validation_results["issues_found"]:
        print(f"\n🚨 Issues Found:")
        for issue in validation_results["issues_found"]:
            print(f"   - {issue}")

    return validation_results

if __name__ == "__main__":
    asyncio.run(validate_endpoints())
