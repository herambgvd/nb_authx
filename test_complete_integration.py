#!/usr/bin/env python3
"""
Complete Integration Test Suite for AuthX
Tests both authentication and user management functionality with comprehensive logging
"""
import asyncio
import httpx
import json
import logging
import sys
from datetime import datetime
from typing import Dict, Any, Optional
import traceback

# Configure comprehensive logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('integration_tests.log')
    ]
)

logger = logging.getLogger(__name__)

class AuthXIntegrationTestSuite:
    """Complete integration test suite for AuthX system."""

    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api/v1"
        self.test_results = []
        self.access_token = None
        self.refresh_token = None
        self.admin_user_id = None
        self.test_user_id = None

    async def log_test_result(self, test_name: str, success: bool, details: Dict[str, Any]):
        """Log test result with detailed information."""
        status = "✅ PASS" if success else "❌ FAIL"
        logger.info(f"{status} - {test_name}")

        if details.get('response_data'):
            logger.debug(f"Response: {json.dumps(details['response_data'], indent=2)}")
        if details.get('error'):
            logger.error(f"Error: {details['error']}")

        self.test_results.append({
            'test_name': test_name,
            'success': success,
            'timestamp': datetime.utcnow().isoformat(),
            'details': details
        })

    def get_auth_headers(self) -> Dict[str, str]:
        """Get authorization headers."""
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }

    async def test_server_health(self, client: httpx.AsyncClient) -> bool:
        """Test if the server is running and responsive."""
        test_name = "Server Health Check"
        logger.info(f"🏥 Testing: {test_name}")

        try:
            response = await client.get(f"{self.base_url}/docs", timeout=10.0)

            if response.status_code == 200:
                await self.log_test_result(test_name, True, {
                    'status_code': response.status_code,
                    'message': 'Server is running and responsive'
                })
                return True
            else:
                await self.log_test_result(test_name, False, {
                    'status_code': response.status_code,
                    'error': 'Server not responding correctly'
                })
                return False

        except Exception as e:
            await self.log_test_result(test_name, False, {
                'error': f'Server connection failed: {str(e)}'
            })
            return False

    async def test_admin_authentication(self, client: httpx.AsyncClient) -> bool:
        """Test admin user authentication."""
        test_name = "Admin Authentication"
        logger.info(f"🔐 Testing: {test_name}")

        try:
            login_data = {
                "username": "admin@acme-corp.example.com",
                "password": "AuthX123!"
            }

            logger.debug("Attempting admin login...")

            response = await client.post(
                f"{self.api_url}/auth/login",
                json=login_data,
                timeout=30.0
            )

            logger.debug(f"Login response status: {response.status_code}")

            if response.status_code == 200:
                data = response.json()
                self.access_token = data.get('access_token')
                self.refresh_token = data.get('refresh_token')
                self.admin_user_id = data.get('user_id')

                await self.log_test_result(test_name, True, {
                    'status_code': response.status_code,
                    'response_data': {
                        'user_id': self.admin_user_id,
                        'organization_id': data.get('organization_id'),
                        'token_type': data.get('token_type'),
                        'expires_in': data.get('expires_in'),
                        'access_token_length': len(self.access_token) if self.access_token else 0
                    }
                })
                return True
            else:
                error_data = response.json() if response.headers.get('content-type') == 'application/json' else response.text
                await self.log_test_result(test_name, False, {
                    'status_code': response.status_code,
                    'error': error_data
                })
                return False

        except Exception as e:
            await self.log_test_result(test_name, False, {
                'error': str(e),
                'exception_type': type(e).__name__,
                'traceback': traceback.format_exc()
            })
            return False

    async def test_token_validation(self, client: httpx.AsyncClient) -> bool:
        """Test token validation with authenticated request."""
        test_name = "Token Validation"
        logger.info(f"🎫 Testing: {test_name}")

        if not self.access_token:
            await self.log_test_result(test_name, False, {
                'error': 'No access token available'
            })
            return False

        try:
            response = await client.get(
                f"{self.api_url}/auth/me",
                headers=self.get_auth_headers(),
                timeout=30.0
            )

            logger.debug(f"Token validation response status: {response.status_code}")

            if response.status_code == 200:
                data = response.json()

                await self.log_test_result(test_name, True, {
                    'status_code': response.status_code,
                    'response_data': {
                        'user_id': data.get('id'),
                        'email': data.get('email'),
                        'username': data.get('username'),
                        'is_active': data.get('is_active'),
                        'is_superuser': data.get('is_superuser')
                    }
                })
                return True
            else:
                error_data = response.json() if response.headers.get('content-type') == 'application/json' else response.text
                await self.log_test_result(test_name, False, {
                    'status_code': response.status_code,
                    'error': error_data
                })
                return False

        except Exception as e:
            await self.log_test_result(test_name, False, {
                'error': str(e),
                'exception_type': type(e).__name__
            })
            return False

    async def test_create_new_user(self, client: httpx.AsyncClient) -> bool:
        """Test creating a new user."""
        test_name = "Create New User"
        logger.info(f"👤 Testing: {test_name}")

        try:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            user_data = {
                "email": f"testuser_{timestamp}@example.com",
                "username": f"testuser_{timestamp}",
                "password": "TestUser123!",
                "first_name": "Test",
                "last_name": "User"
            }

            logger.debug(f"Creating user: {user_data['email']}")

            response = await client.post(
                f"{self.api_url}/users/",
                json=user_data,
                headers=self.get_auth_headers(),
                timeout=30.0
            )

            logger.debug(f"Create user response status: {response.status_code}")

            if response.status_code == 201:
                data = response.json()
                self.test_user_id = data.get('id')

                await self.log_test_result(test_name, True, {
                    'status_code': response.status_code,
                    'response_data': {
                        'user_id': self.test_user_id,
                        'email': data.get('email'),
                        'username': data.get('username'),
                        'is_active': data.get('is_active'),
                        'is_verified': data.get('is_verified')
                    }
                })
                return True
            else:
                error_data = response.json() if response.headers.get('content-type') == 'application/json' else response.text
                await self.log_test_result(test_name, False, {
                    'status_code': response.status_code,
                    'error': error_data
                })
                return False

        except Exception as e:
            await self.log_test_result(test_name, False, {
                'error': str(e),
                'exception_type': type(e).__name__
            })
            return False

    async def test_user_crud_operations(self, client: httpx.AsyncClient) -> bool:
        """Test complete user CRUD operations."""
        test_name = "User CRUD Operations"
        logger.info(f"🔄 Testing: {test_name}")

        if not self.test_user_id:
            await self.log_test_result(test_name, False, {
                'error': 'No test user ID available'
            })
            return False

        try:
            # Test GET user
            get_response = await client.get(
                f"{self.api_url}/users/{self.test_user_id}",
                headers=self.get_auth_headers(),
                timeout=30.0
            )

            if get_response.status_code != 200:
                await self.log_test_result(test_name, False, {
                    'error': f'GET user failed with status {get_response.status_code}'
                })
                return False

            # Test UPDATE user
            update_data = {
                "first_name": "Updated",
                "last_name": "User",
                "bio": "This is an updated bio"
            }

            update_response = await client.put(
                f"{self.api_url}/users/{self.test_user_id}",
                json=update_data,
                headers=self.get_auth_headers(),
                timeout=30.0
            )

            if update_response.status_code != 200:
                await self.log_test_result(test_name, False, {
                    'error': f'UPDATE user failed with status {update_response.status_code}'
                })
                return False

            # Test LIST users
            list_response = await client.get(
                f"{self.api_url}/users/",
                headers=self.get_auth_headers(),
                timeout=30.0
            )

            if list_response.status_code != 200:
                await self.log_test_result(test_name, False, {
                    'error': f'LIST users failed with status {list_response.status_code}'
                })
                return False

            await self.log_test_result(test_name, True, {
                'response_data': {
                    'get_status': get_response.status_code,
                    'update_status': update_response.status_code,
                    'list_status': list_response.status_code,
                    'updated_user': update_response.json()
                }
            })
            return True

        except Exception as e:
            await self.log_test_result(test_name, False, {
                'error': str(e),
                'exception_type': type(e).__name__
            })
            return False

    async def test_password_operations(self, client: httpx.AsyncClient) -> bool:
        """Test password change operations."""
        test_name = "Password Operations"
        logger.info(f"🔑 Testing: {test_name}")

        if not self.test_user_id:
            await self.log_test_result(test_name, False, {
                'error': 'No test user ID available'
            })
            return False

        try:
            password_data = {
                "current_password": "TestUser123!",
                "new_password": "NewPassword123!"
            }

            response = await client.post(
                f"{self.api_url}/users/{self.test_user_id}/change-password",
                json=password_data,
                headers=self.get_auth_headers(),
                timeout=30.0
            )

            logger.debug(f"Password change response status: {response.status_code}")

            if response.status_code == 200:
                data = response.json()

                await self.log_test_result(test_name, True, {
                    'status_code': response.status_code,
                    'response_data': data
                })
                return True
            else:
                error_data = response.json() if response.headers.get('content-type') == 'application/json' else response.text
                await self.log_test_result(test_name, False, {
                    'status_code': response.status_code,
                    'error': error_data
                })
                return False

        except Exception as e:
            await self.log_test_result(test_name, False, {
                'error': str(e),
                'exception_type': type(e).__name__
            })
            return False

    async def test_user_activation_deactivation(self, client: httpx.AsyncClient) -> bool:
        """Test user activation and deactivation."""
        test_name = "User Activation/Deactivation"
        logger.info(f"🔄 Testing: {test_name}")

        if not self.test_user_id:
            await self.log_test_result(test_name, False, {
                'error': 'No test user ID available'
            })
            return False

        try:
            # Test deactivation
            deactivate_response = await client.post(
                f"{self.api_url}/users/{self.test_user_id}/deactivate",
                headers=self.get_auth_headers(),
                timeout=30.0
            )

            if deactivate_response.status_code != 200:
                await self.log_test_result(test_name, False, {
                    'error': f'Deactivation failed with status {deactivate_response.status_code}'
                })
                return False

            # Test activation
            activate_response = await client.post(
                f"{self.api_url}/users/{self.test_user_id}/activate",
                headers=self.get_auth_headers(),
                timeout=30.0
            )

            if activate_response.status_code != 200:
                await self.log_test_result(test_name, False, {
                    'error': f'Activation failed with status {activate_response.status_code}'
                })
                return False

            await self.log_test_result(test_name, True, {
                'response_data': {
                    'deactivate_status': deactivate_response.status_code,
                    'activate_status': activate_response.status_code
                }
            })
            return True

        except Exception as e:
            await self.log_test_result(test_name, False, {
                'error': str(e),
                'exception_type': type(e).__name__
            })
            return False

    async def run_complete_test_suite(self) -> Dict[str, Any]:
        """Run the complete integration test suite."""
        logger.info("🚀 Starting Complete AuthX Integration Test Suite")
        logger.info("=" * 60)

        start_time = datetime.utcnow()

        async with httpx.AsyncClient() as client:
            # Define test sequence
            tests = [
                ("Infrastructure", self.test_server_health),
                ("Authentication", self.test_admin_authentication),
                ("Token Validation", self.test_token_validation),
                ("User Creation", self.test_create_new_user),
                ("User CRUD", self.test_user_crud_operations),
                ("Password Management", self.test_password_operations),
                ("User State Management", self.test_user_activation_deactivation),
            ]

            passed = 0
            total = len(tests)

            for category, test_func in tests:
                logger.info(f"\n📋 Testing Category: {category}")
                logger.info("-" * 40)

                try:
                    result = await test_func(client)
                    if result:
                        passed += 1
                        logger.info(f"✅ {category} tests completed successfully")
                    else:
                        logger.error(f"❌ {category} tests failed")

                    # Small delay between test categories
                    await asyncio.sleep(1.0)

                except Exception as e:
                    logger.error(f"❌ {category} test execution failed: {e}")
                    logger.error(traceback.format_exc())

        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds()

        # Generate comprehensive summary
        summary = {
            'test_suite': 'AuthX Complete Integration Tests',
            'total_tests': total,
            'passed': passed,
            'failed': total - passed,
            'success_rate': (passed / total) * 100 if total > 0 else 0,
            'duration_seconds': duration,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'test_results': self.test_results,
            'system_info': {
                'server_url': self.base_url,
                'api_version': 'v1',
                'test_timestamp': datetime.utcnow().isoformat()
            }
        }

        # Log comprehensive summary
        logger.info("\n" + "=" * 60)
        logger.info("📊 COMPLETE TEST SUITE SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Total Test Categories: {total}")
        logger.info(f"Passed: {passed}")
        logger.info(f"Failed: {total - passed}")
        logger.info(f"Success Rate: {summary['success_rate']:.1f}%")
        logger.info(f"Total Duration: {duration:.2f} seconds")
        logger.info(f"Test Results Saved: integration_test_results.json")

        return summary

async def main():
    """Main test execution function."""
    print("🧪 AuthX Complete Integration Test Suite")
    print("=" * 60)
    print("Testing both authentication and user management functionality")
    print("with comprehensive logging and debugging information.")
    print("=" * 60)

    test_suite = AuthXIntegrationTestSuite()
    summary = await test_suite.run_complete_test_suite()

    # Save comprehensive results to file
    with open('integration_test_results.json', 'w') as f:
        json.dump(summary, f, indent=2)

    print("\n" + "=" * 60)
    print("🎯 FINAL RESULTS")
    print("=" * 60)

    if summary['success_rate'] == 100:
        print("🎉 ALL INTEGRATION TESTS PASSED!")
        print("✅ Authentication system is fully functional")
        print("✅ User management system is fully functional")
        print("✅ All async database operations working correctly")
        print("✅ Comprehensive logging and error handling working")
        sys.exit(0)
    else:
        print(f"💥 {summary['failed']} TEST CATEGORY(IES) FAILED!")
        print("❌ Some functionality may not be working correctly")
        print("📋 Check integration_test_results.json for detailed information")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
