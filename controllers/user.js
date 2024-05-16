const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const router = require("express").Router();
const userModel = require("../models/user");

router.post("/login", async (request, response) => {
    let { Id_Credencial, Password, Source } = request.body;

    if (!Id_Credencial) {
        return response
            .status(400)
            .json({ error: "Id_Credencial is required" });
    }

    Id_Credencial = Id_Credencial.toLowerCase();
    Source = Source ? Source.toLowerCase() : "";

    let user;
    if (Id_Credencial.includes("@")) {
        user = await userModel.findOne({
            Email: Id_Credencial,
        });
    } else {
        user = await userModel.findOne({
            Id_Credencial: Id_Credencial,
        });
    }

    let passwordCorrect = false;
    if (Source === "lector") {
        passwordCorrect = true;
    } else {
        Password = Password ? Password : "";
        passwordCorrect =
            user === null ? false : await bcrypt.compare(Password, user.Hash);
    }

    if (!(user && passwordCorrect)) {
        return response.status(401).json({
            error: "invalid username or password",
        });
    }

    if (!user) {
        return response.status(404).json({
            error: "User not found",
        });
    }

    const userForToken = {
        id: user._id,
    };

    const token = jwt.sign(userForToken, process.env.SECRET);

    response.status(200).send({
        token,
        Nombre: user.Nombre,
        Email: user.Email,
        Id_Credencial: user.Id_Credencial,
        id: user._id,
    });
});

router.post("/signup", async (request, response) => {
    const { Id_Credencial, Nombre, Password, Email } = request.body;

    const lowerCaseCorreo = Email.toLowerCase();
    const lowercaseIdCredencial = Id_Credencial.toLowerCase();

    // Check if user already exists
    const existingUser = await userModel.findOne({
        Id_Credencial: lowercaseIdCredencial,
    });
    if (existingUser) {
        return response
            .status(400)
            .json({ error: "Ya existe un usuario con ese ID" });
    }

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(Password, saltRounds);

    const user = new userModel({
        Id_Credencial: lowercaseIdCredencial,
        Nombre: Nombre,
        Hash: passwordHash,
        Email: lowerCaseCorreo,
    });

    const savedUser = await user.save();

    response.status(201).json(savedUser);
});

router.get("/", async (request, response) => {
    const users = await userModel.find({});
    response.json(users);
});

router.delete("/:id", async (request, response) => {
    await userModel.findByIdAndDelete(request.params.id);
    response.status(204).end();
});

router.put("/:id", async (request, response) => {
    const { Id_Credencial, Nombre, id, Email, Password } = request.body;

    const lowerCaseCorreo = Email.toLowerCase();
    const lowercaseIdCredencial = Id_Credencial.toLowerCase();

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(Password, saltRounds);

    const user = {
        Id_Credencial: lowercaseIdCredencial,
        Nombre: Nombre,
        id: id,
        Email: lowerCaseCorreo,
        Hash: passwordHash,
    };

    const updatedUser = await userModel.findByIdAndUpdate(
        request.params.id,
        user,
        { new: true }
    );
    response.json(updatedUser);
});

module.exports = router;
