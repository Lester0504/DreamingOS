import { mount as mountCommunity } from '/static/desktop/community/community.js?v=20261004-community-01';
export function mount(context={}) { return mountCommunity({...context,host:'traditional'}); }
