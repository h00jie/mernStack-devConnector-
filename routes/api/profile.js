const express = require('express')
const router = express.Router()
const { check, validationResult } = require('express-validator')
const request = require('request')
const config = require('config')
const auth = require('../../middleware/auth')

const Profile = require('../../models/Profile')
const User = require('../../models/User')
const Post = require('../../models/Post')
const { response } = require('express')

// @route   GET api/profile/me
// @desc    Get current users profile route
// @access Private
router.get('/me', auth, async (req, res) => {
  try {
    const profile = await Profile.findOne({
      user: req.user._id,
    }).populate('user', ['name', 'avatar'])

    if (!profile) {
      return res.status(400).json({ msg: 'There is no profile for this user' })
    }

    res.json(profile)
  } catch (error) {
    console.error(err.message)
    res.status(500).send('Server Error')
  }
})

// @route   POST api/profile
// @desc    Create or update user profile
// @access Private
router.post(
  '/',
  [
    auth,
    [
      check('status', 'Status is required').not().isEmpty(),
      check('skills', 'Skills are required').not().isEmpty(),
    ],
  ],
  async (req, res) => {
    const errors = validationResult(req)

    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() })
    }

    const {
      company,
      website,
      location,
      bio,
      status,
      githubusername,
      skills,
      youtube,
      facebook,
      twitter,
      instagram,
      linkedin,
    } = req.body

    // Build profile object
    const profileFields = {}
    profileFields.user = req.user._id
    if (company) profileFields.company = company
    if (website) profileFields.website = website
    if (location) profileFields.location = location
    if (bio) profileFields.bio = bio
    if (status) profileFields.status = status
    if (githubusername) profileFields.githubusername = githubusername
    if (skills) {
      profileFields.skills = Array.isArray(skills)
        ? skills
        : skills.split(',').map((skill) => ' ' + skill.trim())
    }

    // Build Social Object
    profileFields.social = {}
    if (youtube) profileFields.social.youtube = youtube
    if (twitter) profileFields.social.twitter = twitter
    if (facebook) profileFields.social.facebook = facebook
    if (linkedin) profileFields.social.linkedin = linkedin
    if (instagram) profileFields.social.instagram = instagram

    try {
      let profile = await Profile.findOne({ user: req.user._id })

      if (profile) {
        // If found profile Update profile
        profile = await Profile.findOneAndUpdate(
          { user: req.user._id },
          { $set: profileFields },
          { new: true }
        )

        return res.json(profile)
      }

      // If not found profile Create
      profile = new Profile(profileFields)

      await profile.save()

      res.json(profile)
    } catch (error) {
      console.error(error.message)
      res.status(500).send('Server Error')
    }
  }
)

// @route   GET api/profile
// @desc    Get all profiles
// @access Public
router.get('/', async (req, res) => {
  try {
    const profiles = await Profile.find().populate('user', ['name', 'avatar'])
    res.json(profiles)
  } catch (error) {
    console.error(error.message)
    res.status(500).send('Server Error')
  }
})

// @route   GET api/profile/user/:user_id
// @desc    Get profiles by user id
// @access Public
router.get('/user/:user_id', async (req, res) => {
  try {
    const profile = await Profile.findOne({
      user: req.params.user_id,
    }).populate('user', ['name', 'avatar'])

    if (!profile) {
      return res.status(400).json({ msg: 'Profile not found' })
    }
    res.json(profile)
  } catch (error) {
    console.error(error.message)
    if (error.kind === 'ObjectId') {
      return res.status(400).json({ msg: 'Profile not found' })
    }
    res.status(500).send('Server Error')
  }
})

// @route   DELETE api/profile
// @desc    Delete profile, user & posts
// @access Private
router.delete('/', auth, async (req, res) => {
  try {
    console.log(req.user)
    // Remove users posts
    await Post.deleteMany({ user: req.user._id })
    // Remove profile
    await Profile.findOneAndRemove({ user: req.user._id })

    // Remove user
    await User.findByIdAndRemove({ _id: req.user._id })

    res.json({ msg: 'User deleted' })
  } catch (error) {
    console.error(error.message)
    res.status(500).send('Server Error')
  }
})

// ==================== PROFILE EXPERIENCE ROUTES ====================

// @route   PUT api/profile/experience
// @desc    Add profile experience to user
// @access Private
router.put(
  '/experience',
  [
    auth,
    [
      check('title', 'Title is required').not().isEmpty(),
      check('company', 'Company is required').not().isEmpty(),
      check('from', 'From date is required').not().isEmpty(),
    ],
  ],
  async (req, res) => {
    const errors = validationResult(req)

    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() })
    }

    const {
      title,
      company,
      location,
      from,
      to,
      current,
      description,
    } = req.body

    const newExp = {
      title,
      company,
      location,
      from,
      to,
      current,
      description,
    }

    try {
      // Find profile of user coming from request
      const profile = await Profile.findOne({ user: req.user._id })

      // Push the experience to the begging of the object
      profile.experience.unshift(newExp)

      await profile.save()

      res.json(profile)
    } catch (error) {
      console.error(error.message)
      res.status(500).send('Server Error')
    }
  }
)

// @route   PUT api/profile/experience/:exp_id
// @desc    Update profile experience to user
// @access Private
router.put(
  '/experience/:exp_id',
  [
    auth,
    [
      check('title', 'Title is required').not().isEmpty(),
      check('company', 'Company is required').not().isEmpty(),
      check('from', 'From date is required').not().isEmpty(),
    ],
  ],
  async (req, res) => {
    const errors = validationResult(req)

    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errrors.array() })
    }

    const {
      title,
      company,
      location,
      from,
      to,
      current,
      description,
    } = req.body

    try {
      // Find profile of user coming from request
      const profile = await Profile.findOne({ user: req.user._id })

      // Get update experience index
      const updateIndex = profile.experience
        .map((item) => item._id)
        .indexOf(req.params.exp_id)

      if (title !== '') {
        profile.experience[updateIndex].title = title
      }

      if (company !== '') {
        profile.experience[updateIndex].company = company
      }

      if (location !== '') {
        profile.experience[updateIndex].location = location
      }

      if (from !== '') {
        profile.experience[updateIndex].from = from
      }

      if (to !== '') {
        profile.experience[updateIndex].to = to
      }

      if (from !== '') {
        profile.experience[updateIndex].current = current
      }

      if (description !== '') {
        profile.experience[updateIndex].description = description
      }

      await profile.save()

      res.json(profile)
    } catch (error) {
      console.error(error.message)
      res.status(500).send('Server Error')
    }
  }
)

// @route   DELETE api/profile/experience/:exp_id
// @desc    Delete profile experience to user
// @access Private
router.delete('/experience/:exp_id', auth, async (req, res) => {
  try {
    // Find profile of user coming from request
    const profile = await Profile.findOne({ user: req.user._id })
    // Get remove index
    const removeIndex = profile.experience
      .map((item) => item._id)
      .indexOf(req.params.exp_id)

    profile.experience.splice(removeIndex, 1)

    await profile.save()

    res.json(profile)
  } catch (error) {
    console.error(error.message)
    res.status(500).send('Server Error')
  }
})

// ==================== PROFILE EDUCATION ROUTES ====================

// @route   PUT api/profile/education
// @desc    Add profile education to user
// @access Private
router.put(
  '/education',
  [
    auth,
    [
      check('school', 'School is required').not().isEmpty(),
      check('degree', 'Degree is required').not().isEmpty(),
      check('fieldofstudy', 'Field of study is required').not().isEmpty(),
      check('from', 'From date is required').not().isEmpty(),
    ],
  ],
  async (req, res) => {
    const errors = validationResult(req)

    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errrors.array() })
    }

    const {
      school,
      degree,
      fieldofstudy,
      from,
      to,
      current,
      description,
    } = req.body

    const newEdu = {
      school,
      degree,
      fieldofstudy,
      from,
      to,
      current,
      description,
    }

    try {
      // Find profile of user coming from request
      const profile = await Profile.findOne({ user: req.user._id })

      // Push the experience to the begging of the object
      profile.education.unshift(newEdu)

      await profile.save()

      res.json(profile)
    } catch (error) {
      console.error(error.message)
      res.status(500).send('Server Error')
    }
  }
)

// @route   PUT api/profile/education/:exp_id
// @desc    Update profile education to user
// @access Private
router.put(
  '/education/:edu_id',
  [
    auth,
    [
      check('school', 'School is required').not().isEmpty(),
      check('degree', 'Degree is required').not().isEmpty(),
      check('fieldofstudy', 'Field of study is required').not().isEmpty(),
      check('from', 'From date is required').not().isEmpty(),
    ],
  ],
  async (req, res) => {
    const errors = validationResult(req)

    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errrors.array() })
    }

    const {
      school,
      degree,
      fieldofstudy,
      from,
      to,
      current,
      description,
    } = req.body

    try {
      // Find profile of user coming from request
      const profile = await Profile.findOne({ user: req.user._id })

      // Get update experience index
      const updateIndex = profile.education
        .map((item) => item._id)
        .indexOf(req.params.edu_id)

      if (school !== '') {
        profile.education[updateIndex].school = school
      }

      if (degree !== '') {
        profile.education[updateIndex].degree = degree
      }

      if (fieldofstudy !== '') {
        profile.education[updateIndex].fieldofstudy = fieldofstudy
      }

      if (from !== '') {
        profile.education[updateIndex].from = from
      }

      if (to !== '') {
        profile.education[updateIndex].to = to
      }

      if (from !== '') {
        profile.education[updateIndex].current = current
      }

      if (description !== '') {
        profile.education[updateIndex].description = description
      }

      await profile.save()

      res.json(profile)
    } catch (error) {
      console.error(error.message)
      res.status(500).send('Server Error')
    }
  }
)

// @route   DELETE api/profile/education/:exp_id
// @desc    Delete profile education to user
// @access Private
router.delete('/education/:edu_id', auth, async (req, res) => {
  try {
    // Find profile of user coming from request
    const profile = await Profile.findOne({ user: req.user._id })
    // Get remove index
    const removeIndex = profile.education
      .map((item) => item._id)
      .indexOf(req.params.exp_id)

    profile.education.splice(removeIndex, 1)

    await profile.save()

    res.json(profile)
  } catch (error) {
    console.error(error.message)
    res.status(500).send('Server Error')
  }
})

// @route   GET api/profile/github/:username
// @desc    Get user repos from Github
// @access Public
router.get('/github/:username', (req, res) => {
  try {
    const options = {
      uri: `https://api.github.com/users/${
        req.params.username
      }/repos?per_page=5&sort=created:asc&client_id=${config.get(
        'githubClientId'
      )}&client_secret=${config.get('githubSecret')}`,
      method: 'GET',
      headers: { 'user-agent': 'node.js' },
    }

    request(options, (error, response, body) => {
      if (error) console.error(error)

      if (response.statusCode !== 200) {
        return res.status(404).json({ msg: 'No Github profile found' })
      }

      res.json(JSON.parse(body))
    })
  } catch (error) {
    console.error(error.message)
    res.status(500).send('Server Error')
  }
})

module.exports = router
