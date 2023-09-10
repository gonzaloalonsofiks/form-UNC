import bcryptjs from "bcryptjs";
import jsonwebtoken from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const usuarios = [{
  user: "a",
  email: "a@a.com",
  password: "$2a$05$nLY2It8riku2vwwDIINdgO/XIyPXRg1Gn9LFgnhwKqC4TwcAwEUL2"
}];

async function login(req, res) {
  const { user, password } = req.body;

  if (!user || !password) {
    return res.status(400).send({ status: "Error", message: "Los campos están incompletos" });
  }

  const usuarioAResvisar = usuarios.find(usuario => usuario.user === user);

  if (!usuarioAResvisar || !(await bcryptjs.compare(password, usuarioAResvisar.password))) {
    return res.status(400).send({ status: "Error", message: "Error durante el inicio de sesión" });
  }

  const token = jsonwebtoken.sign(
    { user: usuarioAResvisar.user },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRATION }
  );

  const cookieOption = {
    expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000),
    path: "/"
  };

  res.cookie("jwt", token, cookieOption);
  res.send({ status: "ok", message: "Usuario loggeado", redirect: "/admin" });
}

async function register(req, res) {
  const { user, password, email } = req.body;

  if (!user || !password || !email) {
    return res.status(400).send({ status: "Error", message: "Los campos están incompletos" });
  }

  if (usuarios.some(usuario => usuario.user === user)) {
    return res.status(400).send({ status: "Error", message: "Este usuario ya existe" });
  }

  const salt = await bcryptjs.genSalt(5);
  const hashPassword = await bcryptjs.hash(password, salt);
  const nuevoUsuario = { user, email, password: hashPassword };

  usuarios.push(nuevoUsuario);

  return res.status(201).send({ status: "ok", message: `Usuario ${nuevoUsuario.user} agregado`, redirect: "/" });
}

export const methods = { login, register };

import jsonwebtoken from "jsonwebtoken";
import dotenv from "dotenv";
import { usuarios } from "./authentication.controller.js";

dotenv.config();

function revisarCookie(req) {
  try {
    const cookieJWT = req.headers.cookie.split("; ").find(cookie => cookie.startsWith("jwt=")).slice(4);
    const decodificada = jsonwebtoken.verify(cookieJWT, process.env.JWT_SECRET);

    if (!usuarios.some(usuario => usuario.user === decodificada.user)) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

export const methods = {
  soloAdmin: (req, res, next) => {
    const logueado = revisarCookie(req);
    if (logueado) return next();
    return res.redirect("/");
  },
  soloPublico: (req, res, next) => {
    const logueado = revisarCookie(req);
    if (!logueado) return next();
    return res.redirect("/admin");
  }
};

import express from "express";
import cookieParser from "cookie-parser";
import path from "path";
import { fileURLToPath } from "url";
import { methods as authentication } from "./controllers/authentication.controller.js";
import { methods as authorization } from "./middlewares/authorization.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

app.set("port", 4000);
app.listen(app.get("port"));
console.log("Servidor corriendo en puerto", app.get("port"));

app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());
app.use(cookieParser());

app.get("/", authorization.soloPublico, (req, res) => res.sendFile(path.join(__dirname, "pages/login.html")));
app.get("/register", authorization.soloPublico, (req, res) => res.sendFile(path.join(__dirname, "pages/register.html")));
app.get("/admin", authorization.soloAdmin, (req, res) => res.sendFile(path.join(__dirname, "pages/admin/admin.html")));
app.post("/api/login", authentication.login);
app.post("/api/register", authentication.register);

document.getElementById("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const user = e.target.children.user.value;
  const password = e.target.children.password.value;

  try {
    const res = await fetch("http://localhost:4000/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user, password })
    });

    if (!res.ok) {
      // Handle error
    } else {
      const resJson = await res.json();
      if (resJson.redirect) {
        window.location.href = resJson.redirect;
      }
    }
  } catch (error) {
    console.error(error);
  }
});

// Other JavaScript code here
