import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import dotenv from "dotenv/config.js";
import Users from "./models/userSchema.js";
import { validationResult } from "express-validator";
import TokenBlacklist from "./models/blacklist.js";

const secretKey = process.env.secretKey;

export const auth = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  const { oldPassword } = req.body;
  try {
    const { email } = jwt.verify(token, secretKey);
    const user = await Users.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: "User doesn't exist" });
    }

    const passwordMatch = await bcrypt.compare(oldPassword, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    req.authorized = true;
    req.email = email;
    next();
  } catch (error) {
    res.status(401).json({ message: "Unauthorized" });
  }
};

export const authUser = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  try {
    if (token) {
      const data = jwt.verify(token, secretKey);
      req.id = data?.id;
    }
    next();
  } catch (error) {
    res.status(401).json({ message: "unauthorized" });
  }
};

export const checkTokenExpiration = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  try {
    if (token) {
      const decodedToken = jwt.decode(token);

      if (Date.now() >= decodedToken.exp * 1000) {
        const user = { email: decodedToken.email, id: decodedToken.id };
        const renewedToken = jwt.sign(user, secretKey, { expiresIn: "15m" });
        res.setHeader("Authorization", `Bearer ${renewedToken}`);
        req.token = renewedToken;
      } else {
        req.token = token;
      }

      const verifiedToken = jwt.verify(req.token, secretKey);

      const isBlacklisted = await TokenBlacklist.exists({ token });

      if (isBlacklisted) {
        return res.status(401).json({ message: "Unauthorized" });
      }

      req.user = verifiedToken;
    }
    next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid token" });
  }
};

export const isLoggedIn = (req, res, next ) => {
    req.isAuthenticated() ? next() : res.status(401).json({message: "unauthorized"});
}

export const Validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    let error = {};
    errors.array().map((err) => (error[err.param] = err.msg));
    return res.status(422).json({ error });
  }
  next();
};