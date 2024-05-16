const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const router = require("express").Router();
const crypto = require("crypto");
const userModel = require("../models/user");

// Ruta para iniciar sesión (verificar usuario y contraseña y obtener un token)
router.post("/login", async (request, response) => {
    let { Id_Credencial, Password, Source } = request.body;

    // La contraseña y el source son opcionales puesto que depende si el login
    // viene de un lector o de un inicio de sesión convencional, sin embargo, en
    // cualquiera de los casos, el Id_Credencial es obligatorio para identificar
    // al usuario que intenta iniciar sesión.
    if (!Id_Credencial) {
        return response
            .status(400)
            .json({ error: "Id_Credencial is required" });
    }

    // Se convierten a minúsculas para evitar problemas de mayúsculas y
    // minúsculas
    Id_Credencial = Id_Credencial.toLowerCase();
    Source = Source ? Source.toLowerCase() : "";

    // Dependiendo si se recibio un correo o un Id_Credencial, es la manera en
    // la que se busca si el usuario existe en la base de datos.
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

    // En caso de venir el login desde un lector, no se verifica la contraseña
    // por lo que se asigna un valor de true a la variable passwordCorrect, de
    // lo contrario, se verifica que la contraseña sea correcta usando el hash
    // que esta almacenado en la base de datos.
    let passwordCorrect = false;
    if (Source === "lector") {
        passwordCorrect = true;
    } else {
        Password = Password ? Password : "";
        passwordCorrect =
            user === null ? false : await bcrypt.compare(Password, user.Hash);
    }

    // Si el usuario no existe o la contraseña es incorrecta, se regresa un
    // error
    if (!(user && passwordCorrect)) {
        return response.status(401).json({
            error: "invalid username or password",
        });
    }

    // Generar un hash HMAC con la contraseña del usuario y el secretKey
    // Esto sera utilizado para verificar que la contraseña del usuario no haya
    // cambiado y por ende, sea necesario invalidar el token.
    const passwordHashHMAC = crypto
        .createHmac("sha256", process.env.SECRET)
        .update(user.Hash)
        .digest("hex");

    // Informacion que incluirá el token (por si acaso alguna implementacion
    // necesita decriptar el token para obtener información del usuario)
    const tokenInfo = {
        id: user._id,
        Nombre: user.Nombre,
        Email: user.Email,
        Id_Credencial: user.Id_Credencial,
        passwordHashHMAC: passwordHashHMAC,
    };

    // Se genera el token, si el login viene de un lector, el token expirará en
    // 10 minutos, de lo contrario, expirará en 1 día.
    let token;
    if (Source === "lector") {
        token = jwt.sign(tokenInfo, process.env.SECRET, {
            expiresIn: "10m",
        });
    } else {
        token = jwt.sign(tokenInfo, process.env.SECRET, {
            expiresIn: "1d",
        });
    }

    // Se regresa el token y la información del usuario
    response.status(200).send({
        token,
        Nombre: user.Nombre,
        Email: user.Email,
        Id_Credencial: user.Id_Credencial,
        id: user._id,
    });
});

router.post("/verificarToken", async (request, response) => {
    const token = request.body.token;

    // Si no se recibe un token, se regresa un error
    if (!token) {
        return response.status(400).json({ error: "Token is required" });
    }

    try {
        // Decodificamos el token usando el secretKey para obtener todos los
        // datos que se incluyeron en el token
        const decoded = jwt.verify(token, process.env.SECRET);

        // Buscamos al usuario en la base de datos
        const user = await userModel.findOne({
            Id_Credencial: decoded.Id_Credencial,
        });

        // Si el usuario no existe, se regresa un error
        if (!user) {
            return response.status(401).json({ error: "Invalid token" });
        }

        // Se genera un hash HMAC con la contraseña del usuario y el secretKey,
        // esto se usara para compararlo con el hash que se incluyo en el token
        // y asi verificar que la contraseña del usuario no haya cambiado.
        const currentPasswordHashHMAC = crypto
            .createHmac("sha256", process.env.SECRET)
            .update(user.Hash)
            .digest("hex");

        // Si el hash que se incluyo en el token no coincide con el hash
        // generado, entonces significa que la contraseña del usuario ha sido
        // cambiada y por ende, el token es invalido.
        if (decoded.passwordHashHMAC !== currentPasswordHashHMAC) {
            return response
                .status(401)
                .json({ error: "Password has been changed" });
        }

        // Si todo esta correcto, se regresa un valor indicando que se verifico
        // correctamente y los datos del usuario
        response.status(200).json({
            valid: true,
            data: {
                Id_Credencial: decoded.Id_Credencial,
                Email: decoded.Email,
                Nombre: decoded.Nombre,
            },
        });
    } catch (error) {
        response.status(401).json({ error: "Invalid token" });
    }
});

// Ruta para registrar un nuevo usuario
router.post("/signup", async (request, response) => {
    const { Id_Credencial, Nombre, Password, Email } = request.body;

    const lowerCaseCorreo = Email.toLowerCase();
    const lowercaseIdCredencial = Id_Credencial.toLowerCase();

    // Checar si el usuario ya existe para no permitir duplicados
    const existingUser = await userModel.findOne({
        Id_Credencial: lowercaseIdCredencial,
    });
    if (existingUser) {
        return response
            .status(400)
            .json({ error: "Ya existe un usuario con ese ID" });
    }

    // Se encripta la contraseña
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(Password, saltRounds);

    // Se crea el usuario
    const user = new userModel({
        Id_Credencial: lowercaseIdCredencial,
        Nombre: Nombre,
        Hash: passwordHash,
        Email: lowerCaseCorreo,
    });

    // Se guarda el usuario en la base de datos
    const savedUser = await user.save();

    response.status(201).json(savedUser);
});

// Ruta para obtener a todos los usuarios
router.get("/", async (request, response) => {
    const users = await userModel.find({});
    response.json(users);
});

// Ruta para borrar a un usuario
router.delete("/:id", async (request, response) => {
    await userModel.findByIdAndDelete(request.params.id);
    response.status(204).end();
});

// Ruta para actualizar a un usuario
router.put("/:id", async (request, response) => {
    const { Id_Credencial, Nombre, id, Email, Password } = request.body;

    // Se convierten a minúsculas para evitar problemas de mayúsculas y
    // minúsculas
    const lowerCaseCorreo = Email.toLowerCase();
    const lowercaseIdCredencial = Id_Credencial.toLowerCase();

    // Se encripta la contraseña
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(Password, saltRounds);

    // Se actualiza el usuario
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

    // Se regresa el usuario actualizado
    response.json(updatedUser);
});

module.exports = router;
