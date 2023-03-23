/*global TextEncoder, console*/
import {messages_to_scalars, numberToHex} from '../lib/BBS.js';

const messages = [
  'FirstName: Sequoia',
  'LastName: Sempervirens',
  'Address: Jedediah Smith Redwoods State Park, California',
  'Date of Birth: 1200/03/21',
  'Height: 296 feet',
  'Eyes: None',
  'Hair: Brown bark, green needles',
  'Picture: Encoded photo',
  'License Class: None, Trees can\'t drive'
];

const te = new TextEncoder(); // To convert strings to byte arrays
const messagesOctets = messages.map(msg => te.encode(msg));
const msg_scalars = await messages_to_scalars(messagesOctets);
for(let i = 0; i < messages.length; i++) {
  console.log(`msg ${i} ${messages[i]}`);
  console.log(`scalar (hex): ${numberToHex(msg_scalars[i], 32)}`);
}
