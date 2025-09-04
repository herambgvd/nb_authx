#!/usr/bin/env python3
"""
Comprehensive Authentication Test Suite for AuthX
Tests all authentication functionality with detailed logging and debugging
"""
import asyncio
import httpx
import json
import logging
import sys
from datetime import datetime
from typing import Dict, Any, Optional
from uuid import UUID

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('auth_tests.log')
    ]
)

logger = logging.getLogger(__name__)

class AuthTestSuite:
    """Comprehensive authentication test suite with detailed logging."""

    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api/v1"
        self.test_results = []
        self.access_token = None
        self.refresh_token = None
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

    async def test_user_registration(self, client: httpx.AsyncClient) -> bool:
        """Test user registration functionality."""
        test_name = "User Registration"
        logger.info(f"🧪 Testing: {test_name}")

        try:
            # Test data
            test_email = f"testuser_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}@example.com"
            registration_data = {
                "email": test_email,
                "username": f"testuser_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
                "password": "TestPassword123!",
                "first_name": "Test",
                "last_name": "User"
            }

            logger.debug(f"Registration data: {json.dumps(registration_data, indent=2)}")

            response = await client.post(
                f"{self.api_url}/auth/register",
                json=registration_data,
                timeout=30.0
            )

            logger.debug(f"Registration response status: {response.status_code}")
            logger.debug(f"Registration response headers: {dict(response.headers)}")

            if response.status_code == 201:
                data = response.json()
                self.test_user_id = data.get('user_id')

                await self.log_test_result(test_name, True, {
                    'status_code': response.status_code,
                    'response_data': data,
                    'user_id': self.test_user_id
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

    async def test_user_login(self, client: httpx.AsyncClient) -> bool:
        """Test user login functionality."""
        test_name = "User Login"
        logger.info(f"🧪 Testing: {test_name}")

        try:
            # Use seeded admin user
            login_data = {
                "username": "admin@acme-corp.example.com",
                "password": "AuthX123!"
            }

            logger.debug(f"Login data: {json.dumps(login_data, indent=2)}")

            response = await client.post(
                f"{self.api_url}/auth/login",
                json=login_data,
                timeout=30.0
            )

            logger.debug(f"Login response status: {response.status_code}")
            logger.debug(f"Login response headers: {dict(response.headers)}")

            if response.status_code == 200:
                data = response.json()
                self.access_token = data.get('access_token')
                self.refresh_token = data.get('refresh_token')

                await self.log_test_result(test_name, True, {
                    'status_code': response.status_code,
                    'response_data': {
                        'access_token_length': len(self.access_token) if self.access_token else 0,
                        'refresh_token_length': len(self.refresh_token) if self.refresh_token else 0,
                        'user_id': data.get('user_id'),
                        'organization_id': data.get('organization_id'),
                        'token_type': data.get('token_type'),
                        'expires_in': data.get('expires_in')
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

    async def test_token_refresh(self, client: httpx.AsyncClient) -> bool:
        """Test token refresh functionality."""
        test_name = "Token Refresh"
        logger.info(f"🧪 Testing: {test_name}")

        if not self.refresh_token:
            await self.log_test_result(test_name, False, {
                'error': 'No refresh token available for testing'
            })
            return False

        try:
            refresh_data = {
                "refresh_token": self.refresh_token
            }

            logger.debug(f"Refresh data: {json.dumps(refresh_data, indent=2)}")

            response = await client.post(
                f"{self.api_url}/auth/refresh",
                json=refresh_data,
                timeout=30.0
            )

            logger.debug(f"Refresh response status: {response.status_code}")

            if response.status_code == 200:
                data = response.json()
                new_access_token = data.get('access_token')

                await self.log_test_result(test_name, True, {
                    'status_code': response.status_code,
                    'response_data': {
                        'new_access_token_length': len(new_access_token) if new_access_token else 0,
                        'token_type': data.get('token_type'),
                        'expires_in': data.get('expires_in')
                    }
                })

                # Update access token for subsequent tests
                if new_access_token:
                    self.access_token = new_access_token

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

    async def test_authenticated_request(self, client: httpx.AsyncClient) -> bool:
        """Test authenticated request functionality."""
        test_name = "Authenticated Request"
        logger.info(f"🧪 Testing: {test_name}")

        if not self.access_token:
            await self.log_test_result(test_name, False, {
                'error': 'No access token available for testing'
            })
            return False

        try:
            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json"
            }

            logger.debug(f"Request headers: {json.dumps(headers, indent=2)}")

            response = await client.get(
                f"{self.api_url}/auth/me",
                headers=headers,
                timeout=30.0
            )

            logger.debug(f"Authenticated request response status: {response.status_code}")

            if response.status_code == 200:
                data = response.json()

                await self.log_test_result(test_name, True, {
                    'status_code': response.status_code,
                    'response_data': {
                        'user_id': data.get('id'),
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

    async def test_invalid_credentials(self, client: httpx.AsyncClient) -> bool:
        """Test login with invalid credentials."""
        test_name = "Invalid Credentials Handling"
        logger.info(f"🧪 Testing: {test_name}")

        try:
            # Test with invalid credentials
            login_data = {
                "username": "invalid@example.com",
                "password": "wrongpassword"
            }

            logger.debug(f"Invalid login data: {json.dumps(login_data, indent=2)}")

            response = await client.post(
                f"{self.api_url}/auth/login",
                json=login_data,
                timeout=30.0
            )

            logger.debug(f"Invalid login response status: {response.status_code}")

            # Should return 401 for invalid credentials
            if response.status_code == 401:
                await self.log_test_result(test_name, True, {
                    'status_code': response.status_code,
                    'message': 'Correctly rejected invalid credentials'
                })
                return True
            else:
                await self.log_test_result(test_name, False, {
                    'status_code': response.status_code,
                    'error': 'Should have returned 401 for invalid credentials'
                })
                return False

        except Exception as e:
            await self.log_test_result(test_name, False, {
                'error': str(e),
                'exception_type': type(e).__name__
            })
            return False

    async def test_password_change(self, client: httpx.AsyncClient) -> bool:
        """Test password change functionality."""
        test_name = "Password Change"
        logger.info(f"🧪 Testing: {test_name}")

        if not self.access_token:
            await self.log_test_result(test_name, False, {
                'error': 'No access token available for testing'
            })
            return False

        try:
            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json"
            }

            password_data = {
                "current_password": "AuthX123!",
                "new_password": "NewPassword123!"
            }

            logger.debug(f"Password change request initiated")

            response = await client.post(
                f"{self.api_url}/auth/password/change",
                json=password_data,
                headers=headers,
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

    async def run_all_tests(self) -> Dict[str, Any]:
        """Run all authentication tests."""
        logger.info("🚀 Starting Comprehensive Authentication Test Suite")

        start_time = datetime.utcnow()

        async with httpx.AsyncClient() as client:
            # Test sequence
            tests = [
                self.test_user_login,
                self.test_token_refresh,
                self.test_authenticated_request,
                self.test_invalid_credentials,
                self.test_password_change,
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
    print("🧪 AuthX Authentication Test Suite")
    print("=" * 50)

    test_suite = AuthTestSuite()
    summary = await test_suite.run_all_tests()

    # Save results to file
    with open('auth_test_results.json', 'w') as f:
        json.dump(summary, f, indent=2)

    print("\n" + "=" * 50)
    if summary['success_rate'] == 100:
        print("🎉 ALL TESTS PASSED!")
        sys.exit(0)
    else:
        print(f"💥 {summary['failed']} TEST(S) FAILED!")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
