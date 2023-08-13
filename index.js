import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import authRoutes from "./authRoutes.js";
import "./google-oauth.js";
import passport from "passport";
import session from "express-session";
import { isLoggedIn } from "./middleware.js";
import dotenv from "dotenv/config.js";
import YAML from "yamljs";
import swaggerUi from "swagger-ui-express"

const swaggerJsDocs = YAML.load('./swagger.yaml')

const app = express();

app.use('/docs',swaggerUi.serve, swaggerUi.setup(swaggerJsDocs));

app.use(cors());
app.use(express.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false },
  })
);

app.use(passport.initialize());
app.use(passport.session());

app.use("/user", authRoutes);

app.get("/home", (req, res) => {
  res.send('<a href="/auth/google">Login</a>');
});

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["email", "profile"], prompt: "select_account" })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    successRedirect: "/auth/google/success",
    failureRedirect: "/auth/google/failure",
  })
);

app.get("/auth/google/success", isLoggedIn, (req, res) => {
  const user = req.user;
  res.json({ user });
});

app.get("/auth/google/failure", isLoggedIn, (req, res) => {
  res.send("Something went wrong");
});

const PORT = process.env.PORT || 5000;
mongoose
  .connect(process.env.CONNECTION_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() =>
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`))
  )
  .catch((error) => console.log(error.message));
