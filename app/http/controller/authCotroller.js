const User = require("../../models/user");
const bcrypt = require("bcrypt");
const passport = require("passport");

function authController() {
  const _getRedirectUrl = (req) => {
    return req.user.role === 'admin' ? '/admin/orders' : '/customer/orders'
  }
  return {
    login(req, res) {
      res.render("auth/login");
    },

    postlogin(req, res, next) {

      const {mobile, password } = req.body;
      //Validate request
      if (!mobile || !password) {
        req.flash("error", "All fields are required");
        return res.redirect("/login");
      }

      passport.authenticate("local", (err, user, info) => {
        if (err) {
          req.flash("error", info.message);
          return next(err);
        }
        if (!user) {
          req.flash("error", info.message);
          return res.redirect("/login");
        }
        req.login(user, (err)=>{
          if(err){
            req.flash('error', info.message ) 
            return next(err)
          }

          return res.redirect(_getRedirectUrl(req))

        })
      })(req, res, next)
    },

    register(req, res) {
      res.render("auth/register");
    },
    async postRegister(req, res) {
      const { name, mobile, password } = req.body;

      //Validate request
      if (!name || !mobile || !password) {
        req.flash("error", "All fields are required");
        req.flash("name", name);
        req.flash("mobile", mobile);
        return res.redirect("/register");
      }

      // Check if mobile exists
      User.exists({ mobile: mobile }, (err, result) => {
        if (result) {
          req.flash("error", "Email already taken");
          req.flash("name", name);
          req.flash("mobile", mobile);
          return res.redirect("/register");
        }
      });
      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Create a user
      const user = new User({
        name,
        mobile,
        password: hashedPassword,
      });

      user
        .save()
        .then((user) => {
          //Login

          return res.redirect("/");
        })
        .catch((err) => {
          req.flash("error", "Something went wrong");
          return res.redirect("/register");
        });
    },
    logout(req, res) {
      req.logout()
      return res.redirect('/login')
    }
  };
}
module.exports = authController;
