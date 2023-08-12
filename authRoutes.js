import express from "express";
import { login, register, resetPassword, getUser,logout } from "./controllers.js";
import {
  auth,
  authUser,
  checkTokenExpiration,
  Validate,
} from "./middleware.js";
import { check } from "express-validator";

const router = express.Router();

router.post(
  "/login",
  check("email")
    .isEmail()
    .withMessage("Enter a valid email address")
    .normalizeEmail(),
  check("password").not().isEmpty(),
  Validate,
  login
);

router.post(
  "/register",
  [
    check("firstName").notEmpty().withMessage("First name is required"),
    check("lastName").notEmpty().withMessage("Last name is required"),
    check("email").isEmail().withMessage("Invalid email address"),
    check("password")
      .isLength({ min: 6 })
      .withMessage("Password must be at least 6 characters"),
    check("confirmPassword").custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error("Passwords do not match");
      }
      return true;
    }),
  ],
  Validate,
  register
);
router.post("/resetPassword", checkTokenExpiration, auth, resetPassword);
router.get("/getUser/:id?", checkTokenExpiration, authUser, getUser);
router.get("/logout",checkTokenExpiration, logout);

export default router;
