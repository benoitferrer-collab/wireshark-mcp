const {test}=require('node:test');
const assert=require('node:assert/strict');
const {filterCommands}=require('../static/js/engineering-ui.js');
const commands=[{title:'Vue globale',detail:'Synthèse de la capture'},{title:'Flux réseau',detail:'Sessions TCP et échanges'},{title:'DNS',detail:'Protocoles et résolution'},{title:'Assistants IA',detail:'Activité MCP'}];
test('command search finds accents, mixed case and multiple words',()=>{
 assert.equal(filterCommands(commands,'RESEAU')[0].title,'Flux réseau');
 assert.equal(filterCommands(commands,'sessions tcp')[0].title,'Flux réseau');
 assert.equal(filterCommands(commands,'mcp')[0].title,'Assistants IA');
 assert.equal(filterCommands(commands,'introuvable').length,0);
});
test('search keeps the full navigation on an empty query and does not mutate it',()=>{
 assert.equal(filterCommands(commands,'  ').length,4);
 filterCommands(commands,'tcp');
 assert.equal(commands.length,4);
});
