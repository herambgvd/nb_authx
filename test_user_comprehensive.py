#!/usr/bin/env python3
"""
Comprehensive User Management Test Suite for AuthX
Tests all user CRUD operations with detailed logging and debugging
"""
import asyncio
import httpx
import json
import logging
import sys
from datetime import datetime
from typing import Dict, Any, Optional, List
from uuid import UUID

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('user_tests.log')
    ]
)

logger = logging.getLogger(__name__)

class UserTestSuite:
    """Comprehensive user management test suite with detailed logging."""

    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api/v1"
        self.test_results = []
        self.access_token = None
        self.test_user_id = None
        self.created_users = []

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

    async def authenticate_admin(self, client: httpx.AsyncClient) -> bool:
        """Authenticate as admin user for testing."""
        logger.info("🔐 Authenticating as admin user")

        try:
            login_data = {
                "username": "admin@acme-corp.example.com",
                "password": "AuthX123!"
            }

            response = await client.post(
                f"{self.api_url}/auth/login",
                json=login_data,
                timeout=30.0
            )

            if response.status_code == 200:
                data = response.json()
                self.access_token = data.get('access_token')
                logger.info("✅ Admin authentication successful")
                return True
            else:
                logger.error(f"❌ Admin authentication failed: {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"❌ Admin authentication error: {e}")
            return False

    def get_auth_headers(self) -> Dict[str, str]:
        """Get authorization headers."""
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }

    async def test_create_user(self, client: httpx.AsyncClient) -> bool:
        """Test user creation functionality."""
        test_name = "Create User"
        logger.info(f"🧪 Testing: {test_name}")

        try:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            user_data = {
                "email": f"newuser_{timestamp}@example.com",
                "username": f"newuser_{timestamp}",
                "password": "NewUser123!",
                "first_name": "New",
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
                user_id = data.get('id')
                self.test_user_id = user_id
                self.created_users.append(user_id)

                await self.log_test_result(test_name, True, {
                    'status_code': response.status_code,
                    'response_data': {
                        'user_id': user_id,
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

    async def test_get_user(self, client: httpx.AsyncClient) -> bool:
        """Test get user by ID functionality."""
        test_name = "Get User by ID"
        logger.info(f"🧪 Testing: {test_name}")

        if not self.test_user_id:
            await self.log_test_result(test_name, False, {
                'error': 'No test user ID available'
            })
            return False

        try:
            logger.debug(f"Getting user: {self.test_user_id}")

            response = await client.get(
                f"{self.api_url}/users/{self.test_user_id}",
                headers=self.get_auth_headers(),
                timeout=30.0
            )

            logger.debug(f"Get user response status: {response.status_code}")

            if response.status_code == 200:
                data = response.json()

                await self.log_test_result(test_name, True, {
                    'status_code': response.status_code,
                    'response_data': {
                        'user_id': data.get('id'),
                        'email': data.get('email'),
                        'username': data.get('username'),
                        'full_name': f"{data.get('first_name', '')} {data.get('last_name', '')}".strip(),
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

    async def test_list_users(self, client: httpx.AsyncClient) -> bool:
        """Test list users functionality."""
        test_name = "List Users"
        logger.info(f"🧪 Testing: {test_name}")

        try:
            params = {
                "skip": 0,
                "limit": 10
            }

            logger.debug(f"Listing users with params: {params}")

            response = await client.get(
                f"{self.api_url}/users/",
                params=params,
                headers=self.get_auth_headers(),
                timeout=30.0
            )

            logger.debug(f"List users response status: {response.status_code}")

            if response.status_code == 200:
                data = response.json()
                user_count = len(data) if isinstance(data, list) else 0

                await self.log_test_result(test_name, True, {
                    'status_code': response.status_code,
                    'response_data': {
                        'user_count': user_count,
                        'users': [
                            {
                                'id': user.get('id'),
                                'email': user.get('email'),
                                'username': user.get('username')
                            }
                            for user in (data if isinstance(data, list) else [])[:3]  # Show first 3
                        ]
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

    async def test_update_user(self, client: httpx.AsyncClient) -> bool:
        """Test update user functionality."""
        test_name = "Update User"
        logger.info(f"🧪 Testing: {test_name}")

        if not self.test_user_id:
            await self.log_test_result(test_name, False, {
                'error': 'No test user ID available'
            })
            return False

        try:
            update_data = {
                "first_name": "Updated",
                "last_name": "Name",
                "bio": "Updated user bio"
            }

            logger.debug(f"Updating user {self.test_user_id} with: {update_data}")

            response = await client.put(
                f"{self.api_url}/users/{self.test_user_id}",
                json=update_data,
                headers=self.get_auth_headers(),
                timeout=30.0
            )

            logger.debug(f"Update user response status: {response.status_code}")

            if response.status_code == 200:
                data = response.json()

                await self.log_test_result(test_name, True, {
                    'status_code': response.status_code,
                    'response_data': {
                        'user_id': data.get('id'),
                        'first_name': data.get('first_name'),
                        'last_name': data.get('last_name'),
                        'bio': data.get('bio'),
                        'updated_at': data.get('updated_at')
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

    async def test_change_user_password(self, client: httpx.AsyncClient) -> bool:
        """Test change user password functionality."""
        test_name = "Change User Password"
        logger.info(f"🧪 Testing: {test_name}")

        if not self.test_user_id:
            await self.log_test_result(test_name, False, {
                'error': 'No test user ID available'
            })
            return False

        try:
            password_data = {
                "current_password": "NewUser123!",
                "new_password": "UpdatedPassword123!"
            }

            logger.debug(f"Changing password for user: {self.test_user_id}")

            response = await client.post(
                f"{self.api_url}/users/{self.test_user_id}/change-password",
                json=password_data,
                headers=self.get_auth_headers(),
                timeout=30.0
            )

            logger.debug(f"Change password response status: {response.status_code}")

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

    async def test_get_user_devices(self, client: httpx.AsyncClient) -> bool:
        """Test get user devices functionality."""
        test_name = "Get User Devices"
        logger.info(f"🧪 Testing: {test_name}")

        if not self.test_user_id:
            await self.log_test_result(test_name, False, {
                'error': 'No test user ID available'
            })
            return False

        try:
            logger.debug(f"Getting devices for user: {self.test_user_id}")

            response = await client.get(
                f"{self.api_url}/users/{self.test_user_id}/devices",
                headers=self.get_auth_headers(),
                timeout=30.0
            )

            logger.debug(f"Get user devices response status: {response.status_code}")

            if response.status_code == 200:
                data = response.json()
                devices = data.get('devices', [])

                await self.log_test_result(test_name, True, {
                    'status_code': response.status_code,
                    'response_data': {
                        'device_count': len(devices),
                        'devices': [
                            {
                                'id': device.get('id'),
                                'device_name': device.get('device_name'),
                                'ip_address': device.get('ip_address'),
                                'is_trusted': device.get('is_trusted'),
                                'last_seen': device.get('last_seen')
                            }
                            for device in devices[:3]  # Show first 3
                        ]
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

    async def test_deactivate_user(self, client: httpx.AsyncClient) -> bool:
        """Test deactivate user functionality."""
        test_name = "Deactivate User"
        logger.info(f"🧪 Testing: {test_name}")

        if not self.test_user_id:
            await self.log_test_result(test_name, False, {
                'error': 'No test user ID available'
            })
            return False

        try:
            logger.debug(f"Deactivating user: {self.test_user_id}")

            response = await client.post(
                f"{self.api_url}/users/{self.test_user_id}/deactivate",
                headers=self.get_auth_headers(),
                timeout=30.0
            )

            logger.debug(f"Deactivate user response status: {response.status_code}")

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

    async def test_activate_user(self, client: httpx.AsyncClient) -> bool:
        """Test activate user functionality."""
        test_name = "Activate User"
        logger.info(f"🧪 Testing: {test_name}")

        if not self.test_user_id:
            await self.log_test_result(test_name, False, {
                'error': 'No test user ID available'
            })
            return False

        try:
            logger.debug(f"Activating user: {self.test_user_id}")

            response = await client.post(
                f"{self.api_url}/users/{self.test_user_id}/activate",
                headers=self.get_auth_headers(),
                timeout=30.0
            )

            logger.debug(f"Activate user response status: {response.status_code}")

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

    async def test_delete_user(self, client: httpx.AsyncClient) -> bool:
        """Test delete user functionality."""
        test_name = "Delete User"
        logger.info(f"🧪 Testing: {test_name}")

        if not self.test_user_id:
            await self.log_test_result(test_name, False, {
                'error': 'No test user ID available'
            })
            return False

        try:
            logger.debug(f"Deleting user: {self.test_user_id}")

            response = await client.delete(
                f"{self.api_url}/users/{self.test_user_id}",
                headers=self.get_auth_headers(),
                timeout=30.0
            )

            logger.debug(f"Delete user response status: {response.status_code}")

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

    async def run_all_tests(self) -> Dict[str, Any]:
        """Run all user management tests."""
        logger.info("🚀 Starting Comprehensive User Management Test Suite")

        start_time = datetime.utcnow()

        async with httpx.AsyncClient() as client:
            # First authenticate
            if not await self.authenticate_admin(client):
                logger.error("❌ Failed to authenticate admin user. Cannot proceed with tests.")
                return {
                    'error': 'Authentication failed',
                    'total_tests': 0,
                    'passed': 0,
                    'failed': 0
                }

            # Test sequence
            tests = [
                self.test_create_user,
                self.test_get_user,
                self.test_list_users,
                self.test_update_user,
                self.test_change_user_password,
                self.test_get_user_devices,
                self.test_deactivate_user,
                self.test_activate_user,
                self.test_delete_user,
            ]

            passed = 0
            total = len(tests)

            for test in tests:
                try:
                    result = await test(client)
                    if result:
                        passed += 1

                    # Small delay between tests
                    await asyncio.sleep(0.5)

                except Exception as e:
                    logger.error(f"Test execution failed: {e}")

        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds()

        # Generate summary
        summary = {
            'total_tests': total,
            'passed': passed,
            'failed': total - passed,
            'success_rate': (passed / total) * 100 if total > 0 else 0,
            'duration_seconds': duration,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'test_results': self.test_results
        }

        # Log summary
        logger.info("📊 Test Suite Summary:")
        logger.info(f"   Total Tests: {total}")
        logger.info(f"   Passed: {passed}")
        logger.info(f"   Failed: {total - passed}")
        logger.info(f"   Success Rate: {summary['success_rate']:.1f}%")
        logger.info(f"   Duration: {duration:.2f} seconds")

        return summary

async def main():
    """Main test execution function."""
    print("🧪 AuthX User Management Test Suite")
    print("=" * 50)

    test_suite = UserTestSuite()
    summary = await test_suite.run_all_tests()

    # Save results to file
    with open('user_test_results.json', 'w') as f:
        json.dump(summary, f, indent=2)

    print("\n" + "=" * 50)
    if summary.get('success_rate', 0) == 100:
        print("🎉 ALL TESTS PASSED!")
        sys.exit(0)
    else:
        print(f"💥 {summary.get('failed', 0)} TEST(S) FAILED!")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
