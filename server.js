const express = require('express')
const connectDB = require('./config/db')
const path = require('path')

const app = express()

// Connect database
connectDB()

// Init middleware
app.use(
  express.json({
    extended: false,
    // Bad json format validator
    verify: (req, res, buf, encoding) => {
      try {
        JSON.parse(buf)
      } catch (e) {
        res.status(404).send('JSON parse error, invalid JSON')
        throw Error('invalid JSON')
      }
    },
  })
)
// Bad json format
// app.use(function(err, req, res, next) {
//     if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
//       // Handle the error here
//       console.error('Bad JSON');
//       res.status(500).send('JSON parse error');
//     }

//     // Pass the error to the next middleware if it wasn't a JSON parse error
//     next(err)
// });

// Define Routes
app.use('/api/users', require('./routes/api/users'))
app.use('/api/auth', require('./routes/api/auth'))
app.use('/api/profile', require('./routes/api/profile'))
app.use('/api/posts', require('./routes/api/posts'))

// Serve static assets in production
if (process.env.NODE_ENV === 'production') {
  // Set static folder
  app.use(express.static('client/build'))

  app.get('*', (req, res) => {
    res.sendFile(path.resolve(__dirname, 'client', 'build', 'index.html'))
  })
}

const PORT = process.env.PORT || 5000

app.listen(PORT, () => console.log(`Server started on port ${PORT}`))