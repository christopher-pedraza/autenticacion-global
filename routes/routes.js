const router = require("express").Router();
const user = require("../controllers/user");

router.use("/user", user);

module.exports = router;
