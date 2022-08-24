// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const router = require("express").Router();
const {
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength,
} = require("./auth-middleware");
const { add } = require("../users/users-model");
const bcrypt = require("bcryptjs");
/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 201
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  } 
 */
router.post("/register", checkPasswordLength, checkUsernameFree, async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const hash = bcrypt.hashSync(password, 12);
    const newUser = await add({ username, password: hash });
    console.log(newUser);
    res.status(201).json(newUser);
  } catch (err) {
    next(err);
  }
});

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */
router.post("/login", checkUsernameExists, (req, res, next) => {
  const { password } = req.body;
  if (bcrypt.compareSync(password, req.user.password)) {
    //send the cookie to the client and make it set in the cookie store
    //also make server store a session with a session id
    req.session.user = req.user;
    res.json({ message: `welcome ${req.user.username}!` });
  } else {
    next({ status: 401, message: "Invalid credentials" });
  }
});
/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
router.get("/logout", (req, res, next) => {
  res.json({ message: "logged out" });
});

// Don't forget to add the router to the `exports` object so it can be required in other modules

module.exports = router;
