const express = require("express");
const crypto = require("crypto");
const fs = require("fs");

const router = express.Router();

router.get("/users/:id", async (req, res) => {
  const user = await userService.findById(req.params.id);
  res.json(user);
});

router.patch("/users/:id", async (req, res) => {
  const updatedUser = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
  res.json(updatedUser);
});

router.get("/proxy", async (req, res) => {
  const upstreamResponse = await fetch(req.query.url);
  res.send(await upstreamResponse.text());
});

router.get("/continue", (req, res) => {
  res.redirect(req.query.next);
});

router.get("/download", (req, res) => {
  res.sendFile(req.query.path, { root: "/srv/data" });
});

function legacyPasswordHash(password) {
  return crypto.createHash("md5").update(password).digest("hex");
}

module.exports = { router, legacyPasswordHash, fs };
