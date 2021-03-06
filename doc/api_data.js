define({ "api": [
  {
    "type": "post",
    "url": "/api/confirm-activate?name=Robin&token=JASd1AS4dr7uijsd4TJU",
    "title": "Confirm Activate User",
    "name": "Activate_User",
    "group": "User",
    "version": "1.0.0",
    "parameter": {
      "fields": {
        "params": [
          {
            "group": "params",
            "type": "String",
            "optional": false,
            "field": "name",
            "description": "<p>User's name.</p>"
          },
          {
            "group": "params",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>User's token for activating account.</p>"
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "success",
            "description": "<p>indicates the status of procedure.</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>indicates which user was created.</p>"
          }
        ]
      },
      "examples": [
        {
          "title": "Success-Response:",
          "content": "HTTP/1.1 200 OK\n{\n  \"success\": true,\n  \"message\": \"User activated successfully\"\n}",
          "type": "json"
        }
      ]
    },
    "error": {
      "examples": [
        {
          "title": "Token-Incorrect:",
          "content": "HTTP/1.1 422 Error\n{\n  \"success\": false,\n  \"message\": \"Token is incorrect.\"\n}",
          "type": "json"
        }
      ]
    },
    "filename": "routes/api/auth.js",
    "groupTitle": "User"
  },
  {
    "type": "post",
    "url": "/api/change-password",
    "title": "Change User Password",
    "name": "Change_User_Password",
    "group": "User",
    "version": "1.0.0",
    "parameter": {
      "fields": {
        "Body": [
          {
            "group": "Body",
            "type": "String",
            "optional": false,
            "field": "email",
            "description": "<p>User's email.</p>"
          },
          {
            "group": "Body",
            "type": "String",
            "optional": false,
            "field": "password",
            "description": "<p>User's password.</p>"
          }
        ]
      },
      "examples": [
        {
          "title": "Body:",
          "content": "{\n  \"password\": \"old password\",\n  \"newPassword\": \"new-password\",\n  \"newPassword2\": \"repeat-password\",\n}",
          "type": "json"
        }
      ]
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "success",
            "description": "<p>indicates the status of procedure.</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>indicates which user was created.</p>"
          }
        ]
      },
      "examples": [
        {
          "title": "Success-Response:",
          "content": "HTTP/1.1 200 OK\n{\n  \"success\": true,\n  \"message\": \"User password was changed.\"\n}",
          "type": "json"
        }
      ]
    },
    "error": {
      "examples": [
        {
          "title": "No-Account-Found:",
          "content": "HTTP/1.1 401 Error\n{\n  Unauthorized\n}",
          "type": "json"
        },
        {
          "title": "Current-Password-Incorrect:",
          "content": "HTTP/1.1 403 Error\n{\n  \"success\": false,\n  \"message\": \"Current password is incorrect.\"\n}",
          "type": "json"
        },
        {
          "title": "User-Not-Defined:",
          "content": "HTTP/1.1 403 Error\n{\n  \"success\": false,\n  \"message\": \"User is not defined.\"\n}",
          "type": "json"
        },
        {
          "title": "Account-Not-Active:",
          "content": "HTTP/1.1 400 Error\n{\n  \"success\": false,\n  \"message\": \"Your account is not active.\"\n}",
          "type": "json"
        },
        {
          "title": "Password-Not-Match:",
          "content": "HTTP/1.1 422 Error\n{\n  \"success\": false,\n  \"message\": \"Password should be equal two times.\"\n}",
          "type": "json"
        },
        {
          "title": "Password-Not-Match:",
          "content": "HTTP/1.1 422 Error\n{\n  \"success\": false,\n  \"message\": \"Password should be different.\"\n}",
          "type": "json"
        }
      ]
    },
    "filename": "routes/api/auth.js",
    "groupTitle": "User"
  },
  {
    "type": "post",
    "url": "/api/confirm-recover-password",
    "title": "Confirm Recover Password",
    "name": "Confirm_Recover_Password",
    "group": "User",
    "version": "1.0.0",
    "parameter": {
      "fields": {
        "params": [
          {
            "group": "params",
            "type": "String",
            "optional": false,
            "field": "name",
            "description": "<p>User's name.</p>"
          },
          {
            "group": "params",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>User's token for recover password.</p>"
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "success",
            "description": "<p>indicates the status of procedure.</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>indicates which user was created.</p>"
          }
        ]
      },
      "examples": [
        {
          "title": "Success-Response:",
          "content": "HTTP/1.1 200 OK\n{\n  \"success\": true,\n  \"message\": \"Password was reseted. Please wait for email.\"\n}",
          "type": "json"
        }
      ]
    },
    "error": {
      "examples": [
        {
          "title": "Confirmation-Token-Incorrect:",
          "content": "HTTP/1.1 422 Error\n{\n  \"success\": false,\n  \"message\": \"Confirmation token is incorrect.\"\n}",
          "type": "json"
        }
      ]
    },
    "filename": "routes/api/auth.js",
    "groupTitle": "User"
  },
  {
    "type": "get",
    "url": "/api/auth/facebook",
    "title": "Face Book Login",
    "name": "Face_Book_Login",
    "group": "User",
    "version": "1.0.0",
    "parameter": {
      "fields": {
        "Body": [
          {
            "group": "Body",
            "type": "String",
            "optional": false,
            "field": "email",
            "description": "<p>User's email.</p>"
          },
          {
            "group": "Body",
            "type": "String",
            "optional": false,
            "field": "password",
            "description": "<p>User's password.</p>"
          }
        ]
      },
      "examples": [
        {
          "title": "Body:",
          "content": "{\n  \"email\": \"example@example.com\",\n  \"password\": \"some-password\",\n}",
          "type": "json"
        }
      ]
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "success",
            "description": "<p>indicates the status of procedure.</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>indicates which user was created.</p>"
          }
        ]
      }
    },
    "filename": "routes/api/passport.js",
    "groupTitle": "User"
  },
  {
    "type": "get",
    "url": "/api/profile",
    "title": "Get User's Profile",
    "name": "Get_User_s_Profile",
    "group": "User",
    "version": "1.0.0",
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>user's token.</p>"
          },
          {
            "group": "Success 200",
            "type": "Boolean",
            "optional": false,
            "field": "active",
            "description": "<p>user's active status.</p>"
          },
          {
            "group": "Success 200",
            "type": "Number/null",
            "optional": false,
            "field": "googleId",
            "description": "<p>google's account id.</p>"
          },
          {
            "group": "Success 200",
            "type": "Number/null",
            "optional": false,
            "field": "faceBookId",
            "description": "<p>facebook's account id.</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "_id",
            "description": "<p>user's id.</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "name",
            "description": "<p>user's name.</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "email",
            "description": "<p>user's email.</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "password",
            "description": "<p>user's password.</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "date",
            "description": "<p>date of creatin account.</p>"
          }
        ]
      },
      "examples": [
        {
          "title": "Success-Response:",
          "content": "{\n   \"token\": \"hWL6eQRisuu0H8tnYqmewLl8kPDLFUYG\",\n   \"active\": true,\n   \"googleId\": null,\n   \"faceBookId\": null,\n   \"_id\": \"5d7969d239396c65ca989657\",\n   \"name\": \"Josh\",\n   \"email\": \"andrii.zilnyk@gmail.com\",\n   \"password\": \"$2a$10$pPDb/ZiGtRNDBflQfs6yC.rxSIy9bXDYUSCt38AFdfT3VT5BEitc.\",\n   \"date\": \"2019-09-11T21:40:34.248Z\",\n   \"__v\": 0\n}",
          "type": "json"
        }
      ]
    },
    "filename": "routes/api/auth.js",
    "groupTitle": "User"
  },
  {
    "type": "get",
    "url": "/api/auth/facebook",
    "title": "Google Login",
    "name": "Google_Login",
    "group": "User",
    "version": "1.0.0",
    "parameter": {
      "fields": {
        "Body": [
          {
            "group": "Body",
            "type": "String",
            "optional": false,
            "field": "email",
            "description": "<p>User's email.</p>"
          },
          {
            "group": "Body",
            "type": "String",
            "optional": false,
            "field": "password",
            "description": "<p>User's password.</p>"
          }
        ]
      },
      "examples": [
        {
          "title": "Body:",
          "content": "{\n  \"email\": \"example@example.com\",\n  \"password\": \"some-password\",\n}",
          "type": "json"
        }
      ]
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "success",
            "description": "<p>indicates the status of procedure.</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>indicates which user was created.</p>"
          }
        ]
      }
    },
    "filename": "routes/api/passport.js",
    "groupTitle": "User"
  },
  {
    "type": "post",
    "url": "/api/login",
    "title": "Login User",
    "name": "Login_User",
    "group": "User",
    "version": "1.0.0",
    "parameter": {
      "fields": {
        "Body": [
          {
            "group": "Body",
            "type": "String",
            "optional": false,
            "field": "email",
            "description": "<p>User's email.</p>"
          },
          {
            "group": "Body",
            "type": "String",
            "optional": false,
            "field": "password",
            "description": "<p>User's password.</p>"
          }
        ]
      },
      "examples": [
        {
          "title": "Body:",
          "content": "{\n  \"email\": \"example@example.com\",\n  \"password\": \"some-password\",\n}",
          "type": "json"
        }
      ]
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "success",
            "description": "<p>indicates the status of procedure.</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>indicates which user was created.</p>"
          }
        ]
      }
    },
    "error": {
      "examples": [
        {
          "title": "No-Account-Found:",
          "content": "HTTP/1.1 404 Error\n{\n  \"success\": false,\n  \"message\": \"No account found.\"\n}",
          "type": "json"
        },
        {
          "title": "Password-Incorrect:",
          "content": "HTTP/1.1 403 Error\n{\n  \"success\": false,\n  \"message\": \"Password is incorrect.\"\n}",
          "type": "json"
        },
        {
          "title": "Account-Not-Active:",
          "content": "HTTP/1.1 403 Error\n{\n  \"success\": false,\n  \"message\": \"Your account is not active.\"\n}",
          "type": "json"
        }
      ]
    },
    "filename": "routes/api/auth.js",
    "groupTitle": "User"
  },
  {
    "type": "post",
    "url": "/api/logout",
    "title": "Logout",
    "name": "Logout_User",
    "group": "User",
    "version": "1.0.0",
    "success": {
      "examples": [
        {
          "title": "Success-Response:",
          "content": "HTTP/1.1 200 OK",
          "type": "json"
        }
      ]
    },
    "filename": "routes/api/auth.js",
    "groupTitle": "User"
  },
  {
    "type": "post",
    "url": "/api/recover-password",
    "title": "Recover Password",
    "name": "Recover_Password",
    "group": "User",
    "version": "1.0.0",
    "parameter": {
      "fields": {
        "Body": [
          {
            "group": "Body",
            "type": "String",
            "optional": false,
            "field": "email",
            "description": "<p>User's email.</p>"
          },
          {
            "group": "Body",
            "type": "String",
            "optional": false,
            "field": "password",
            "description": "<p>User's password.</p>"
          }
        ]
      },
      "examples": [
        {
          "title": "Body:",
          "content": "{\n  \"name\": \"Smith\",\n  \"email\": \"example@gmail.com\"\n}",
          "type": "json"
        }
      ]
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "success",
            "description": "<p>indicates the status of procedure.</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>indicates which user was created.</p>"
          }
        ]
      },
      "examples": [
        {
          "title": "Success-Response:",
          "content": "HTTP/1.1 200 OK\n{\n  \"success\": true,\n  \"message\": \"Confirmation email was sent to your email.\"\n}",
          "type": "json"
        }
      ]
    },
    "error": {
      "examples": [
        {
          "title": "User-Not-Found:",
          "content": "HTTP/1.1 404 Error\n{\n  \"success\": false,\n  \"message\": \"User was not found.\"\n}",
          "type": "json"
        },
        {
          "title": "User-Not-Defined:",
          "content": "HTTP/1.1 422 Error\n{\n  \"success\": false,\n  \"message\": \"Your account is not active.\"\n}",
          "type": "json"
        },
        {
          "title": "Information-Incorrect:",
          "content": "HTTP/1.1 422 Error\n{\n  \"success\": false,\n  \"message\": \"User name or email is incorrect.\"\n}",
          "type": "json"
        }
      ]
    },
    "filename": "routes/api/auth.js",
    "groupTitle": "User"
  },
  {
    "type": "post",
    "url": "/api/register",
    "title": "Register new User",
    "name": "Register_User",
    "group": "User",
    "version": "1.0.0",
    "parameter": {
      "fields": {
        "Body": [
          {
            "group": "Body",
            "type": "String",
            "optional": false,
            "field": "name",
            "description": "<p>User's name.</p>"
          },
          {
            "group": "Body",
            "type": "String",
            "optional": false,
            "field": "email",
            "description": "<p>User's email.</p>"
          },
          {
            "group": "Body",
            "type": "String",
            "optional": false,
            "field": "password",
            "description": "<p>User's password.</p>"
          }
        ]
      },
      "examples": [
        {
          "title": "Body:",
          "content": "{\n  \"name\": \"Nick\",\n  \"email\": \"example@example.com\",\n  \"password\": \"some-password\",\n}",
          "type": "json"
        }
      ]
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "success",
            "description": "<p>indicates the status of procedure.</p>"
          },
          {
            "group": "Success 200",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>indicates which user was created.</p>"
          }
        ]
      },
      "examples": [
        {
          "title": "Success-Response:",
          "content": "HTTP/1.1 200 OK\n{\n  \"active\": false,\n  \"_id\": \"5d7969d239396c65ca989657\",\n  \"name\": \"5d7969d239396c65ca989657\",\n  \"email\": \"5d7969d239396c65ca989657\",\n  \"password\": \"$2a$10$pPDb/ZiGtRNDBflQfs6yC.rxSIy9basL4daAXDYUSCt38AFdfT3VT5BEitc.\",\n  \"date\": \"2019-09-11T21:40:34.248Z\",\n  \"token\": \"sNGCr2g4cGiA1ZezXo4jlYlIzF5gUVXv\",\n}",
          "type": "json"
        }
      ]
    },
    "error": {
      "examples": [
        {
          "title": "Email-Exists:",
          "content": "HTTP/1.1 403 Error\n{\n  \"success\": false,\n  \"message\": \"Email address is already exists in DB.\"\n}",
          "type": "json"
        }
      ]
    },
    "filename": "routes/api/auth.js",
    "groupTitle": "User"
  }
] });
