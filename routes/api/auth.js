const express = require('express')
const { check, validationResult } = require('express-validator')
const jwt = require('jsonwebtoken')
const config = require('config')
const bcrypt = require('bcryptjs')
const router = express.Router()
const auth = require('../../middleware/auth')
const User = require('../../models/User')

// @route   GET api/auth
// @desc    Test route
// @access Public
router.get('/', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password')
    res.json(user)
  } catch (error) {
    console.error(error.message)
    res.status(500).send('Server error')
  }
})

// @route   POST api/users
// @desc    Authenticate user & get token
// @access Public
router.post(
  '/',
  [
    check('email', 'Please provide a valid email').isEmail(),
    check('password', 'Password is required').exists(),
  ],
  async (req, res) => {
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() })
    }

    const { email, password } = req.body

    try {
      // check if user exists in DB
      let user = await User.findOne({ email })
      //  if user exists send 400 response
      if (!user) {
        return res
          .status(400)
          .json({ errors: [{ msg: 'Invalid Credentials' }] })
      }

      const isMatch = await bcrypt.compare(password, user.password)

      if (!isMatch) {
        return res
          .status(400)
          .json({ errors: [{ msg: 'Invalid Credentials' }] })
      }

      const payload = {
        user: {
          _id: user.id,
        },
      }

      // Return jsonwebtoken
      jwt.sign(
        payload,
        config.get('jwtSecret'),
        {
          expiresIn: 36000,
        },
        (err, token) => {
          if (err) throw err
          res.json({ token })
        }
      )
    } catch (error) {
      console.error(error.message)
      res.status(500).send('Server error')
    }
  }
)

module.exports = router
