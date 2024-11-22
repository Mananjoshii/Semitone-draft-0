import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import env from "dotenv";
import multer from "multer"; // For file uploads

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

// Configure multer for file uploads
const upload = multer({ dest: "public/uploads/" });

app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

// Render Home Page
app.get("/", (req, res) => {
  res.render("home.ejs");
});

// Render Login and Register Pages
app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

// Logout User
app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

// Render Profile Page
app.get("/profile", (req, res) => {
  if (req.isAuthenticated()) {
    const userId = req.user.id;
    db.query("SELECT * FROM users WHERE id = $1", [userId], (err, result) => {
      if (err) {
        console.error("Error fetching user data:", err);
        res.redirect("/");
      } else {
        const user = result.rows[0];
        res.render("profile.ejs", { user });
      }
    });
  } else {
    res.redirect("/login");
  }
});

// Update Profile Information
app.post("/profile", (req, res) => {
  if (req.isAuthenticated()) {
    const { bio, instruments, genre, experienceLevel } = req.body;
    const userId = req.user.id;

    db.query(
      "UPDATE users SET bio = $1, instruments = $2, genre = $3, experience_level = $4 WHERE id = $5",
      [bio, instruments, genre, experienceLevel, userId],
      (err) => {
        if (err) {
          console.error("Error updating profile:", err);
        }
        res.redirect("/profile");
      }
    );
  } else {
    res.redirect("/login");
  }
});

// Upload Portfolio Items


app.post('/profile', upload.fields([
  { name: 'profilePicture', maxCount: 1 },
  { name: 'portfolioItem', maxCount: 1 }
]), async (req, res) => {
  const { name, bio, instruments, genre, experienceLevel } = req.body;
  const userId = req.user.id;

  const updatedData = {
    name,
    bio,
    instruments: instruments ? instruments.split(',').map(item => item.trim()) : [],
    genre,
    experienceLevel,
  };

  if (req.files.profilePicture) {
    // Save profile picture path to the database
    updatedData.profilePicture = req.files.profilePicture[0].path;
  }

  if (req.files.portfolioItem) {
    // Save portfolio item path to the database
    const portfolioItem = {
      url: req.files.portfolioItem[0].path,
      type: req.files.portfolioItem[0].mimetype.startsWith('audio') ? 'audio' : 'video',
    };
    await db.query('INSERT INTO portfolio (user_id, url, type) VALUES ($1, $2, $3)', [
      userId, portfolioItem.url, portfolioItem.type,
    ]);
  }

  // Update user profile
  await db.query(
    'UPDATE users SET name = $1, bio = $2, instruments = $3, genre = $4, experience_level = $5 WHERE id = $6',
    [updatedData.name, updatedData.bio, updatedData.instruments, updatedData.genre, updatedData.experienceLevel, userId]
  );

  res.redirect('/profile'); // Redirect to profile page
});


app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/profile",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/profile");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

// Passport Configuration
passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.serializeUser((user, cb) => {
  cb(null, user.id);
});

passport.deserializeUser((id, cb) => {
  db.query("SELECT * FROM users WHERE id = $1", [id], (err, result) => {
    if (err) {
      return cb(err);
    } else {
      return cb(null, result.rows[0]);
    }
  });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
