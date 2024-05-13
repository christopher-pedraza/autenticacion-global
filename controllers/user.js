const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const router = require("express").Router();
const userModel = require("../models/user");

router.post("/login", async (request, response) => {
    const { username, password } = request.body;

    const lowercaseUsername = username.toLowerCase();

    const user = await userModel.findOne({ username: lowercaseUsername });

    const passwordCorrect =
        user === null
            ? false
            : await bcrypt.compare(password, user.passwordHash);

    if (!(user && passwordCorrect)) {
        return response.status(401).json({
            error: "invalid username or password",
        });
    }

    const userForToken = {
        username: user.username,
        id: user._id,
    };

    const token = jwt.sign(userForToken, process.env.SECRET);

    response.status(200).send({
        token,
        username: user.username,
        name: user.name,
        rol: user.rol,
    });
});

router.post("/signup", async (request, response) => {
    const { username, name, password, rol } = request.body;

    const lowercaseUsername = username.toLowerCase();
    const lowerCaseRol = rol.toLowerCase();

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    const user = new userModel({
        username: lowercaseUsername,
        name,
        passwordHash,
        rol: lowerCaseRol,
    });

    const savedUser = await user.save();

    response.status(201).json(savedUser);
});

router.get("/", async (request, response) => {
    const users = await userModel.find({});
    response.json(users);
});

router.get("/:id", async (request, response) => {
    const user = await userModel.findById(request.params.id);
    if (user) {
        response.json(user);
    } else {
        response.status(404).end();
    }
});

router.delete("/:id", async (request, response) => {
    await userModel.findByIdAndDelete(request.params.id);
    response.status(204).end();
});

router.put("/:id", async (request, response) => {
    const { username, name, password, rol } = request.body;

    const lowercaseUsername = username.toLowerCase();
    const lowerCaseRol = rol.toLowerCase();

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    const user = {
        username: lowercaseUsername,
        name,
        passwordHash,
        rol: lowerCaseRol,
    };

    const updatedUser = await userModel.findByIdAndUpdate(
        request.params.id,
        user,
        { new: true }
    );
    response.json(updatedUser);
});

module.exports = router;
