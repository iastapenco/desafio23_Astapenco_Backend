import { Router } from "express";
import passport from "passport";
import { passportError, authorization } from "../utils/messagesError.js";
import { generateToken } from "../utils/jwt.js";
import multer from "multer";
import { userModel } from "../dao/models/users.models.js";

const sessionRouter = Router();
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "src/public/profiles");
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}${file.originalname}`);
  },
});

const upload = multer({ storage: storage });

sessionRouter.get("/login", async (req, res) => {
  res.render("login", {
    js: "session.js",
  });
});

sessionRouter.post(
  "/login",
  passport.authenticate("login"),
  async (req, res) => {
    try {
      if (!req.user) {
        return res.status(401).send({ mensaje: "Usuario inválido" });
      }
      req.user.last_connection = Date.now();
      await req.user.save();

      req.session.user = {
        first_name: req.user.first_name,
        last_name: req.user.last_name,
        age: req.user.age,
        email: req.user.email,
      };

      const token = generateToken(req.user);
      res.cookie("jwtCookie", token, {
        maxAge: 43200000,
      });

      res.status(200).send({ payload: req.user });
    } catch (error) {
      return res
        .status(500)
        .send({ mensaje: `Error al iniciar sesión: ${error} ` });
    }
  }
);

sessionRouter.get(
  "/github",
  passport.authenticate("github", { scope: ["user: email"] }),
  async (req, res) => {
    res.status(200).send({ mensaje: "Usuario registrado" });
  }
);

sessionRouter.get(
  "/githubCallback",
  passport.authenticate("github"),
  async (req, res) => {
    req.session.user = req.user;
    res.status(200).send({ mensaje: "Usuario logueado" });
  }
);

sessionRouter.post(
  "/register",
  passport.authenticate("register"),
  async (req, res) => {
    try {
      if (!req.user) {
        return res.status(400).send({ mensaje: "Usuario ya existente" });
      }

      res.status(200).send({ mensaje: "Usuario registrado" });
    } catch (error) {
      return res
        .status(500)
        .send({ mensaje: `Error al registrar usuario: ${error} ` });
    }
  }
);

sessionRouter.post(
  "/:uid/profileImg",
  upload.single("profile_img"),
  (req, res) => {
    try {
      console.log(req.file);
      res.status(200).send("Imagen de perfil cargada correctamente");
    } catch (error) {
      res
        .status(500)
        .send({ status: "Error al cargar la imagen", error: error });
    }
  }
);

sessionRouter.get("/logout", async (req, res) => {
  if (req.session.user) {
    const user = await userModel.findById(req.session.passport.user);
    if (!user) {
      return res.status(404).send("Usuario no encontrado");
    }

    user.last_connection = Date.now();
    await user.save();
    req.session.destroy();
    res.clearCookie("jwtCookie");
    res.status(200).send({ resultado: "Usuario deslogueado" });
  } else {
    res.status(404).send("El usuario no tiene sesiones activas");
  }
});

sessionRouter.get(
  "/testJWT",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    console.log(req);
    res.send(req.user);
  }
);

sessionRouter.get(
  "/current",
  passportError("jwt"),
  authorization("user"),
  (req, res, next) => {
    res.send(req.user);
  }
);

export default sessionRouter;
