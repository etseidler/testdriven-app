import React from 'react';
import { MemoryRouter as Router } from 'react-router-dom';
import { shallow, mount } from 'enzyme';

import App from '../../App';

beforeAll(() => {
  global.localStorage = {
    getItem: () => 'someToken'
  };
});

test('App renders without crashing', () => {
  const wrapper = shallow(<App />);
});

test('App will call componentWillMount when mounted', () => {
  const onWillMount = jest.fn();
  App.prototype.UNSAFE_componentWillMount = onWillMount;
  const wrapper = mount(<Router><App /></Router>);
  expect(onWillMount).toHaveBeenCalledTimes(1)
});