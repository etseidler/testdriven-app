import React from 'react';

const Message = ({ messageType, removeMessage, messageName }) => {
  return (
    <div className={`notification is-${messageType}`}>
      <button className="delete" onClick={() => { removeMessage() }}></button>
      <span>{messageName}</span>
    </div>
  )
};

export default Message;