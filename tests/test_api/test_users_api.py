from builtins import str
import pytest
from app.main import app
from app.models.user_model import User
from app.utils.nickname_gen import generate_nickname
from app.services.jwt_service import decode_token  # Import your FastAPI app
from urllib.parse import urlencode
from app.utils.security import validate_password_strength

#Example of a test function using the async_client fixture
@pytest.mark.asyncio
async def test_create_user_access_denied(async_client, user_token, email_service):
    headers = {"Authorization": f"Bearer {user_token}"}
    # Define user data for the test
    user_data = {
        "nickname": generate_nickname(),
        "email": "test@example.com",
        "password": "sS#fdasrongPassword123!",
    }
    # Send a POST request to create a user
    response = await async_client.post("/users/", json=user_data, headers=headers)
    # Asserts
    assert response.status_code == 403

# You can similarly refactor other test functions to use the async_client fixture
@pytest.mark.asyncio
async def test_retrieve_user_access_denied(async_client, verified_user, user_token):
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.get(f"/users/{verified_user.id}", headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_retrieve_user_access_allowed(async_client, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    assert response.status_code == 200
    assert response.json()["id"] == str(admin_user.id)

@pytest.mark.asyncio
async def test_update_user_email_access_denied(async_client, verified_user, user_token):
    updated_data = {"email": f"updated_{verified_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.put(f"/users/{verified_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_update_user_email_access_allowed(async_client, admin_user, admin_token):
    updated_data = {"email": f"updated_{admin_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == updated_data["email"]


@pytest.mark.asyncio
async def test_delete_user(async_client, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    delete_response = await async_client.delete(f"/users/{admin_user.id}", headers=headers)
    assert delete_response.status_code == 204
    # Verify the user is deleted
    fetch_response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    assert fetch_response.status_code == 404

@pytest.mark.asyncio
async def test_create_user_duplicate_email(async_client, verified_user):
    user_data = {
        "email": verified_user.email,
        "password": "AnotherPassword123!",
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 400
    assert "Email already exists" in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_create_user_invalid_email(async_client):
    user_data = {
        "email": "notanemail",
        "password": "ValidPassword123!",
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 422

@pytest.mark.asyncio
async def test_login_success(async_client, verified_user):
    # Attempt to login with the test user
    form_data = {
        "username": verified_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    
    # Check for successful login response
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

    # Use the decode_token method from jwt_service to decode the JWT
    decoded_token = decode_token(data["access_token"])
    assert decoded_token is not None, "Failed to decode token"
    assert decoded_token["role"] == "AUTHENTICATED", "The user role should be AUTHENTICATED"

@pytest.mark.asyncio
async def test_login_user_not_found(async_client):
    form_data = {
        "username": "nonexistentuser@here.edu",
        "password": "DoesNotMatter123!"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401
    assert "Incorrect email or password." in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_login_incorrect_password(async_client, verified_user):
    form_data = {
        "username": verified_user.email,
        "password": "IncorrectPassword123!"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401
    assert "Incorrect email or password." in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_login_unverified_user(async_client, unverified_user):
    form_data = {
        "username": unverified_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_login_locked_user(async_client, locked_user):
    form_data = {
        "username": locked_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 400
    assert "Account locked due to too many failed login attempts." in response.json().get("detail", "")
@pytest.mark.asyncio
async def test_delete_user_does_not_exist(async_client, admin_token):
    non_existent_user_id = "00000000-0000-0000-0000-000000000000"  # Valid UUID format
    headers = {"Authorization": f"Bearer {admin_token}"}
    delete_response = await async_client.delete(f"/users/{non_existent_user_id}", headers=headers)
    assert delete_response.status_code == 404

@pytest.mark.asyncio
async def test_update_user_github(async_client, admin_user, admin_token):
    updated_data = {"github_profile_url": "http://www.github.com/kaw393939"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["github_profile_url"] == updated_data["github_profile_url"]

@pytest.mark.asyncio
async def test_update_user_linkedin(async_client, admin_user, admin_token):
    updated_data = {"linkedin_profile_url": "http://www.linkedin.com/kaw393939"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["linkedin_profile_url"] == updated_data["linkedin_profile_url"]

@pytest.mark.asyncio
async def test_list_users_as_admin(async_client, admin_token):

    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    print(decode_token(admin_token))
    assert response.status_code == 200
    assert 'items' in response.json()

@pytest.mark.asyncio
async def test_list_users_as_manager(async_client, manager_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {manager_token}"}
    )
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_list_users_unauthorized(async_client, user_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 403  # Forbidden, as expected for regular user


@pytest.mark.asyncio
async def test_get_user_not_found(async_client, admin_token):
    """
    Ensure that requesting a non-existent user returns 404.
    """
    headers = {"Authorization": f"Bearer {admin_token}"}
    fake_uuid = "00000000-0000-0000-0000-000000000000"
    response = await async_client.get(f"/users/{fake_uuid}", headers=headers)
    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"

@pytest.mark.asyncio
async def test_create_user_duplicate_email_as_admin(async_client, admin_token, verified_user):
    """
    Ensure that creating a user with an existing email returns 400 Bad Request.
    """
    headers = {"Authorization": f"Bearer {admin_token}"}
    user_data = {
        "email": verified_user.email,
        "password": "Secure123!",
        "nickname": "dupeuser"
    }
    response = await async_client.post("/users/", json=user_data, headers=headers)
    assert response.status_code == 400
    assert "Email already exists" in response.json()["detail"]

@pytest.mark.asyncio
async def test_update_user_not_found(async_client, admin_token):
    """
    Ensure 404 is returned when attempting to update a non-existent user.
    """
    headers = {"Authorization": f"Bearer {admin_token}"}
    non_existent_user_id = "00000000-0000-0000-0000-000000000000"
    updated_data = {"bio": "Updated bio"}
    response = await async_client.put(f"/users/{non_existent_user_id}", json=updated_data, headers=headers)
    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"

from unittest.mock import patch

@pytest.mark.asyncio
async def test_create_user_server_error(async_client, admin_token, email_service):
    """
    Ensure 500 is returned if user creation fails after passing all validations.
    """
    headers = {"Authorization": f"Bearer {admin_token}"}
    user_data = {
        "email": "testfail@example.com",
        "password": "Secure123!",
        "nickname": "failure_case"
    }

    with patch("app.services.user_service.UserService.create", return_value=None):
        response = await async_client.post("/users/", json=user_data, headers=headers)
        assert response.status_code == 500
        assert response.json()["detail"] == "Failed to create user"


@pytest.mark.asyncio
async def test_verify_email_invalid_token(async_client, admin_user):
    """
    Ensure 400 is returned if the email verification token is invalid or expired.
    """
    response = await async_client.get(f"/verify-email/{admin_user.id}/invalidtoken")
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid or expired verification token"

from unittest.mock import AsyncMock, patch

@pytest.mark.asyncio
async def test_verify_email_success(async_client, admin_user):
    """
    Ensure email verification returns success message for valid token.
    """
    with patch("app.services.user_service.UserService.verify_email_with_token", new_callable=AsyncMock) as mock_verify:
        mock_verify.return_value = True
        response = await async_client.get(f"/verify-email/{admin_user.id}/validtoken")
        assert response.status_code == 200
        assert response.json()["message"] == "Email verified successfully"

@pytest.mark.asyncio
async def test_create_user_missing_fields(async_client, admin_token):
    """
    Ensure 422 is returned when required fields are missing during user creation.
    """
    headers = {"Authorization": f"Bearer {admin_token}"}
    # Missing password and nickname
    incomplete_data = {
        "email": "missingfields@example.com"
    }
    response = await async_client.post("/users/", json=incomplete_data, headers=headers)
    assert response.status_code == 422

@pytest.mark.asyncio
async def test_update_user_invalid_field(async_client, admin_user, admin_token):
    """
    Ensure 422 is returned when trying to update a user with an invalid field (e.g., invalid URL).
    """
    invalid_data = {
        "github_profile_url": "not-a-valid-url"
    }
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=invalid_data, headers=headers)
    assert response.status_code == 422

@pytest.mark.asyncio
async def test_register_missing_required_fields(async_client):
    """
    Ensure 422 is returned when trying to register a user without required fields like password.
    """
    incomplete_data = {
        "email": "test@missingpassword.com"
    }
    response = await async_client.post("/register/", json=incomplete_data)
    assert response.status_code == 422

@pytest.mark.asyncio
async def test_register_duplicate_email(async_client, verified_user):
    """
    Ensure 400 is returned when attempting to register a user with an already registered email.
    """
    user_data = {
        "email": verified_user.email,
        "password": "AnotherSecurePass123!"
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 400
    assert "Email already exists" in response.json()["detail"]

@pytest.mark.asyncio
async def test_login_duplicate_routes_warning(async_client, verified_user):
    """
    Ensure login still works despite route being declared twice in code (once with include_in_schema=False).
    """
    form_data = {
        "username": verified_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post(
        "/login/",
        data=urlencode(form_data),
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 200
    assert "access_token" in response.json()




