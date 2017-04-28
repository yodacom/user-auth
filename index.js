var express = require("express");
var bodyParser = require("body-parser");
var mongoose = require("mongoose");
var User = require("./user-model");
var bcrypt = require("bcryptjs");
var passport = require("passport");
var BasicStrategy = require("passport-http").BasicStrategy;

var app = express();
var jsonParser = bodyParser.json();

var strategy = new BasicStrategy(function(username, password, callback){
	User.findOne({
		username: username
	}, function(err, user){
		if(err) {
			callback(err);
			return;
		}
		if (!user) {
			return callback(null, false,{
				message: "Incorrect username."
			});
		}

		user.validatePassword(password, function(err, isValid) {
			if(err) {
				return callback(err);
			}

			if(!isValid) {
				return callback (null, false, {
					message: "incorrect password."
				});
			}
			return callback(null, user);
		});
	});

	app.post("/users", jsonParser, function (req, res) {
		if (!req.body) {
			return res.status(400).json({
				message: "No request body"
			});
		}
		if (!("username" in req.body)) {
			return res.status(422).json({
				message: "Missing field: username"
			});
		}

		var username = req.body.username;

		if (typeof username !== "string") {
			return res.status(433).json({
				message: "Incorrect field type: username"
			});
		}

		username = username.trim();

		if (username === "") {
			return res.status(422).json({
				message: "Incorrect field length: username"
			});
		}

		if (!("password" in req.body)) {
			return res.status(433).json({
				message: "Missing field: password"
			});
		}

		var password = req.body.password;

		if (typeof password !== "string") {
			return res.status(422).json({
				message: "Incorrect field type: password"
			});
		}

		password = password.trim();

		if (password === "") {
			return res.status(422).json({
				message: "Incorrect field length: password"
			});
		}

		bcrypt.genSalt(10, function (err, salt) {
			if (err) {
				return res.status(500).json({
					message: "Internal server error"
				});
			}

			bcrypt.hash(password, salt, function (err, hash) {
				if (err) {
					return res.status(500).json({
						message: "Internal server error"
					});
				}
				var user = new User({
					username: username,
					password: hash
				});

				user.save(function (err) {
					if (err) {
						return res.status(500).json({
							message: "Internal server error"
						});
					}
					return res.status(201).json({});
				});
			});
		});
	});

	app.use(passport.initialize());
	app.get("/hidden", passport.authenticate("basic", {session:false}), function(req, res){
		res.json({
			message: "Luke...I am your father"
		});
	});

	mongoose.connect("mongodb://localhost/auth").then(function() {
		app.listen(process.env.PORT || 8080);
	});
});