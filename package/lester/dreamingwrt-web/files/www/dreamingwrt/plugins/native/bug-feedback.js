import { mount as mountFeedback } from '/static/desktop/bug-feedback/bug-feedback.js?v=20261002-support-02';
export function mount(context={}) { return mountFeedback({...context,host:'traditional'}); }
