require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");

const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const GoogleStrategy = require("passport-google-oauth2").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(express.json());

app.use(
  session({
    secret: "OurLittle Secret.",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

mongoose
  .connect("mongodb://localhost:27017/secret_app", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("Connection successful....");
  })
  .catch((err) => {
    console.log(err);
  });

const schema = new mongoose.Schema({
  username: { type: String },
  googleId: { type: String },
  secret: { type: String },
});

schema.plugin(passportLocalMongoose);
schema.plugin(findOrCreate);

const Model = new mongoose.model("Model", schema);

passport.use(Model.createStrategy());

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:2000/auth/google/UserAuth",
      passReqToCallback: true,
    },
    function (request, accessToken, refreshToken, profile, done) {
      Model.findOrCreate(
        { username: profile.displayName, googleId: profile.id },
        function (err, user) {
          return done(err, user);
        }
      );
    }
  )
);

passport.serializeUser(function (user, done) {
  done(null, user);
});

passport.deserializeUser(function (user, done) {
  done(null, user);
});

app.get("/", (req, res) => {
  res.render(__dirname + "/views/home");
});

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["email", "profile"] })
);

app.get(
  "/auth/google/UserAuth",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    res.redirect("/secrets");
  }
);

app.get("/login", (req, res) => {
  res.render(__dirname + "/views/login");
});

app.get("/register", (req, res) => {
  res.render(__dirname + "/views/register");
});

app.get("/secrets", (req, res) => {
  Model.find({ secret: { $ne: null } }, (err, foundUser) => {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        res.render(__dirname + "/views/secrets", { users: foundUser });
      }
    }
  });
});

app.get("/submit", (req, res) => {
  res.render(__dirname + "/views/submit");
});

app.post("/register", async (req, res) => {
  Model.register(
    { username: req.body.username },
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    }
  );
});

app.post("/login", async (req, res) => {
  const user = new Model({
    username: req.body.username,
    password: req.body.password,
  });
  req.login(user, function (err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});

app.get("/logout", function (req, res) {
  req.logout((err) => {
    console.log(err);
  });
  res.redirect("/");
});

app.get("/submit", async (req, res) => {
  if (req.isAuthenticated()) {
    res.render("/secrets");
  } else {
    res.render("/login");
  }
});

app.post("/submit", (req, res) => {
  const submit = req.body.secret;

  Model.findById(req.user._id, (err, foundUser) => {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submit;
        foundUser.save(() => {
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.listen(2000, () => {
  console.log("Server started..");
});
