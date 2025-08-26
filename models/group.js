// models/Group.js
const mongoose = require('mongoose');

const GroupSchema = new mongoose.Schema({
  chatId: { type: String, required: true, unique: true },
  welcome: String,
  goodbye: String,
  autoWarnEnabled: { type: Boolean, default: true }
});

module.exports = mongoose.model('Group', GroupSchema);