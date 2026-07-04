import { useEffect } from 'react';
import { connectSocket } from '@lib/socket';
import { logger } from '@lib/logger';

/**
 * Hook to subscribe to alert stream events. Provides a callback on new alerts.
 */
export const useAlertStream = (onAlert: (payload: unknown) => void) => {
  useEffect(() => {
    const socket = connectSocket();
    const handle = (data: unknown) => {
      logger.debug('socket alert:new', data);
      onAlert(data);
    };
    socket.on('alert:new', handle);
    socket.connect();
    return () => {
      socket.off('alert:new', handle);
      socket.disconnect();
    };
  }, [onAlert]);
};
