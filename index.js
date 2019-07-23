const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const db = require("./database/dbConfig.js");
const Users = require("./users/users-model.js");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const KnexSessionStore = require("connect-session-knex")(session);
const server = express();

const sessionConfig = {
  name: "mordor", // defaults to sid
  secret: process.env.SESSION_SECRET || "keep it secret, keep it safe!", // to encrypt/decrypt the cookie
  cookie: {
    maxAge: 1000 * 60 * 10, // milliseconds
    secure: false, // true in production, only send cookie over https
    httpOnly: true // JS can't access the cookie on the client
  },
  resave: false, // save the session again even if it didn't change
  saveUninitialized: true,
  // GOTCHA: remember to "new" it up
  store: new KnexSessionStore({
    knex: require("./database/dbConfig.js"),
    tablename: "sessions",
    createtable: true,
    sidfieldname: "sid",
    clearInterval: 1000 * 60 * 60 // deletes expired sessions every hour
  })
};
server.use(session(sessionConfig));
server.use(cookieParser());
server.use(helmet());
server.use(express.json());
server.use(cors());

server.get("/", (req, res) => {
  res.cookie("name", "express").send("It's alive!");
});

server.post("/api/register", (req, res) => {
  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(req.body.password, salt);
  let user = {
    username: req.body.username,
    password: hash
  };
  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post("/api/login", (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        req.session.username = user.username;
        res
          .status(200)
          .cookie("user", true, { maxAge: 1000 * 60 * 1 })
          .json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: "Invalid Credentials" });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});
server.post("/api/logout", (req, res) => {
  if (req.session) {
    // here we logout
    req.session.destroy(err => {
      if (err) {
        res.status(500).json({
          message:
            "you can checkout any time you like, but you can never leave..."
        });
      } else {
        res.status(200).json({ message: "bye...." });
      }
    });
  } else {
    res.status(200).json({ message: "ok, bye" });
  }
});
server.get("/api/users", authorizeSession, async (req, res) => {
  console.log("Cookies: ", req.cookies);
  let { username, password } = req.headers;
  let auth = false;
  await Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        auth = true;
      }
    });
  if (auth) {
    Users.find()
      .then(users => {
        res.json(users);
      })
      .catch(err => res.send(err));
  } else {
    res.status(401).json({ message: "Invalid Credentials" });
  }
});

function authorizeSession(req, res, next) {
  if (req.session && req.session.username) {
    next();
  } else {
    res.status(401).json({ message: "YOU SUCK!" });
  }
}

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
