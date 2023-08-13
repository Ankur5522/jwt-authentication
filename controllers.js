import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import Users from "./models/userSchema.js";
import { validationResult } from "express-validator";
import TokenBlacklist from "./models/blacklist.js";
import dotenv from "dotenv/config.js";

const secretKey = process.env.secretKey;

export const login = async (req, res) => {
  const { email, password } = req.body;
  try {
    const existingUser = await Users.findOne({ email });
    if (!existingUser)
      return res.status(404).json({ message: "User doesn't exist" });
    const isPasswordCorrect = await bcrypt.compare(
      password,
      existingUser.password
    );
    if (!isPasswordCorrect)
      return res.status(404).json({ message: "Invalid credentials." });
    const token = jwt.sign(
      { email: existingUser.email, id: existingUser._id },
      secretKey,
      { expiresIn: "1h" }
    );
    res.status(200).json({ userData: existingUser, token });
  } catch (error) {
    res.status(500).json({ message: "Something went wrong with login" });
  }
};

export const register = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  const { firstName, lastName, email, password, confirmPassword } = req.body;

  try {
    const existingUser = await Users.findOne({ email });
    if (existingUser)
      return res.status(409).json({ message: "Users already exist" });

    const hashedPassword = await bcrypt.hash(password, 12);

    const userData = await Users.create({
      email,
      password: hashedPassword,
      name: `${firstName} ${lastName}`,
    });

    const token = jwt.sign(
      { email: userData.email, id: userData._id },
      secretKey,
      { expiresIn: "1h" }
    );

    res.status(201).json({ userData, token });
  } catch (error) {
    res.status(500).json({ message: "Something went wrong with signup" });
  }
};

export const resetPassword = async (req, res) => {
    console.log(req.headers)
  const { newPassword } = req.body;
  try {
    const email = req.email;
    const user = await Users.findOne({ email });
    const id = user._id;
    const hashedPassword = await bcrypt.hash(newPassword, 12);
    const newUserData = { password: hashedPassword };
    const newUser = await Users.findByIdAndUpdate(id, newUserData, {
      new: true,
    });
    res.status(200).json(newUser);
  } catch (error) {
    res.status(500).json({ message: "something went wrong "});
  }
};

export const getUser = async (req, res) => {
  const { id } = req.params;
  let user;
  try {
    if (req.isAuthenticated() && !id) {
      const { id, displayName, emails, photos } = req.user;
      return res.status(200).json({
        userData: {
          id,
          displayName,
          email: emails[0].value,
          photo: photos[0].value,
        },
      });
    }

    if (!req.id) {
      return res.status(401).json({ message: "unauthorized" });
    }
    user = await Users.findById(id);
    res.status(200).json({ userData: user });
  } catch (error) {
    res.status(500).json({ message: "something went wrong" });
  }
};
export const logout = async (req, res) => {
  const token = req.token;
  try {
    if (req.isAuthenticated() && !token) {
        req.session.destroy();
        res.clearCookie('connect.sid');
        res.status(200).json({ message: "Logged out successfully"});
    } else {
      if (token) {
        const expiresAt = new Date(req.user.exp * 1000);
        const blacklistToken = new TokenBlacklist({
          token,
          expiresAt,
        });
        await blacklistToken.save();
        res.status(200).json({ message: "logged out successfully" });
      } else {
        res.status(401).json({ message: "not authenticated" });
      }
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Something went wrong" });
  }
};
