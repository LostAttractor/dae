export const byId = (id) => document.getElementById(id);
export const template = (id) => byId(id).content.firstElementChild.cloneNode(true);
