# This file contains helper functions for the Identity Provider (IdP) service.

"""
Generate a dictionary of user information for authentication purposes.

Args:
  _ (Any): Unused parameter, kept for interface compatibility.
  user (User): The user object containing user details.
  user (User): The user object containing user details.

Returns:
  dict: A dictionary with the following keys:
    - 'sub': The user's unique identifier as a string.
    - 'email': The user's email address.
    - 'name': The user's full name if available, otherwise username.
"""
def userinfo(_, user): 

  return {
    'sub': str(user.id),
    'email': user.email,
    'name': user.get_full_name() or user.username,
  }